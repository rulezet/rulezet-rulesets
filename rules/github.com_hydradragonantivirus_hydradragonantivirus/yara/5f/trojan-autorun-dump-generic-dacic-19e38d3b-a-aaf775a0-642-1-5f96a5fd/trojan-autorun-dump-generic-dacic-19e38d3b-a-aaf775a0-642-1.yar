rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_642_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_642_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e652536ede5d37f4577c16953b5954f8e9b40d280d42ba75348ebbe6098dc37a"

  strings:
    $s1 = "H7and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}