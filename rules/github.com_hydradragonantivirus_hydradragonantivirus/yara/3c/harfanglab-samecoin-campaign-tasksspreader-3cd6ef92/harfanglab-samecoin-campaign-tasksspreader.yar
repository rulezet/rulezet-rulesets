rule HARFANGLAB_Samecoin_Campaign_Tasksspreader: FILE {
  meta:
    description = "Detect .NET Task Scheduler that is dropper by SameCoin Loader"
    author      = "HarfangLab"
    id          = "7dcfdecd-00c3-502a-b29e-a10a1fd9543f"
    date        = "2024-02-13"
    modified    = "2024-04-05"
    reference   = "TRR240201"
    source_url  = "https://github.com/HarfangLab/iocs/blob/f679751df7994790f9f79629d60b3f2623148255/TRR240201/trr240201_yara.yar#L43-L80"
    license_url = "N/A"
    hash        = "b447ba4370d9becef9ad084e7cdf8e1395bafde1d15e82e23ca1b9808fef13a7"
    logic_hash  = "61d602c343365608e5bc587ee9c7898e256f2411d78c7fe74c211e68bf4ab707"
    score       = 75
    quality     = 28
    tags        = "FILE"
    context     = "file"

  strings:
    $dotNet = ".NETFramework,Version" ascii fullword
    $a1     = "System.DirectoryServices.ActiveDirectory" ascii fullword
    $a2     = "GetTypeFromProgID" ascii fullword
    $a3     = "DirectorySearcher" ascii fullword
    $a4     = "SearchResultCollection" ascii fullword
    $a5     = "UnaryOperation" ascii fullword
    $b1     = "$dc1b29f0-9a87-4383-ad8b-01285614def1" ascii fullword
    $b2     = "Windows Defender Agent" ascii fullword
    $b3     = "Windows Defender Agent.exe" wide ascii fullword
    $b4     = /(\\)?C(:|\$)\\Users\\Public\\Microsoft System Agent\.exe/ wide fullword
    $b5     = "MicrosoftEdgeUpdateTaskMachinesCores" wide fullword
    $b6     = "WindowsUpdate" wide fullword
    $c1     = "RegisterTaskDefinition" wide fullword
    $c2     = "DisallowStartIfOnBatteries" wide fullword
    $c3     = "StopIfGoingOnBatteries" wide fullword
    $c4     = "Schedule.Service" wide fullword
    $c5     = "\\Domain Users" wide fullword
    $c6     = "(objectClass=computer)" wide fullword

  condition:
    filesize > 8KB and filesize < 40KB and (uint16be(0) == 0x4D5A) and $dotNet and (4 of ($a*)) and (((any of ($b*)) and (any of ($c*))) or (all of ($c*)))
}