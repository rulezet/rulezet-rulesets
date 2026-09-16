rule VirusShareWin32Expiro150_5_1 {
  meta:
    description = "datamaliciousorder - file VirusShareWin32Expiro150_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68e3a142910403d6d8a6fd941427f0060c18e8f30550b5fe8f4a3ff2ca4992de"

  strings:
    $s1 = "F_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}