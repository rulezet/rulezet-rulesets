rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_22_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6bffcb4a9a7eb5cab0789e497350262ba9ced233acb1ca2d598f756e7e47289"

  strings:
    $s1 = "B(format != NULL)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}