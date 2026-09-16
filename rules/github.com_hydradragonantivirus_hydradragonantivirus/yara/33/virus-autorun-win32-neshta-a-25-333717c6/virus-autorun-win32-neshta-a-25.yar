rule Virus_Autorun_Win32_Neshta_A_25 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b744fff17459b3e2e4d6f07e131ed38ba3c3cd05852bc6a595d19f5c31df3b93"

  strings:
    $s1 = "Copyright 2012. Hancom Inc. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}