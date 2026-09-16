rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1fb2cb6f57b3ef74e095480bdea1d7d0c86fe3296f84c1f893044adcbc63bf"

  strings:
    $s1 = "erms of the GNU General Public License as published by the Free Sof" fullword wide
    $s2 = "name please" fullword ascii
    $s3 = "Pane 1" fullword wide
    $s4 = "Pane 2" fullword wide
    $s5 = "rogram is free software; you can redistribute it and/or modify it under the " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}