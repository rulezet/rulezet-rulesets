rule VirusShareBackDoorBladabindiNET10 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorBladabindiNET10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05fb1f2607fc07650bfef4d68b96e311b21425eabaa9fa8eb5ff0f2274828a36"

  strings:
    $s1 = "Window Security Startup.exe" fullword wide
    $s2 = "Window Security Startup" fullword wide
    $s3 = "C&nOOn&C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}