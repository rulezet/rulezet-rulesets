rule HARFANGLAB_Allasenhamaycampaign_Executorloader {
  meta:
    description = "Detects Delphi ExecutorLoader DLLs and executables."
    author      = "HarfangLab"
    id          = "0a09414d-cd86-54a4-99e4-121a7df7624b"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "TRR240501"
    source_url  = "https://github.com/HarfangLab/iocs/blob/f679751df7994790f9f79629d60b3f2623148255/TRR240501/trr240501_yara.yar#L1-L19"
    license_url = "N/A"
    logic_hash  = "61aa0bf180574856e57d0b26442bfa6f4b1e25844611d6eadaed529e1bb86625"
    score       = 75
    quality     = 55
    tags        = ""
    context     = "file,memory"

  strings:
    $delphi   = "Embarcadero Delphi" ascii fullword
    $s1       = "\\SysWOW64\\mshta.exe" wide fullword
    $s2       = "\\System32\\mshta.exe" wide fullword
    $s3       = "RcDll" wide fullword
    $default1 = "Default_" wide fullword
    $default2 = "Default~" wide fullword

  condition:
    $delphi and all of ($s*) and any of ($default*)
}