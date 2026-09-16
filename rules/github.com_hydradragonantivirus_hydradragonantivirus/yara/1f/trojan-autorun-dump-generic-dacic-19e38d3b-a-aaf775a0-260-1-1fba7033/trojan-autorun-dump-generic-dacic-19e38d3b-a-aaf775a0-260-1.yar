rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_260_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_260_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d3f60fef5f626148ada0652dbbc0e3cc2646d3ff802b14d39e2f66a270d0037"

  strings:
    $s1 = "yule)u\\u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}