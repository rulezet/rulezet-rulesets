rule VirusShareTrojanKillProc216858 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanKillProc216858.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e4bb34270b24afabeda380f853ac329f9eb8449b37b830c1852c252651cc9e"

  strings:
    $s1 = "C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\Debug\\Windows" ascii
    $s2 = "C:\\Users\\Administrator\\Documents\\Visual Studio 2015\\Projects\\WindowsApplication1\\WindowsApplication1\\obj\\Debug\\Windows" ascii
    $s3 = "schtasks /create /sc minute /mo 1 /tn SkypeTHA /tr \"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}