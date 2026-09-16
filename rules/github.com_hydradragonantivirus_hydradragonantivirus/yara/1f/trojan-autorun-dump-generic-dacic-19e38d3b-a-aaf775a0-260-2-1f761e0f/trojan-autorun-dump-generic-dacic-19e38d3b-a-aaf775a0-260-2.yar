rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_260_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_260_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe145d95b6e1479219c11ca9648e23400bf81428a11277ece8535ef53e027f1"

  strings:
    $s1 = "WYDe>k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}