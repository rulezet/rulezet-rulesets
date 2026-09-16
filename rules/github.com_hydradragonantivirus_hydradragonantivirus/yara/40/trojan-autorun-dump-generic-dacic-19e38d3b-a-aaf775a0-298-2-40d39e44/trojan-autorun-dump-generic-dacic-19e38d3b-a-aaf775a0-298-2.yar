rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_298_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_298_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fee20821ffafcc2698e2ecd7d3188ee88b205b6dc7992c49b37df7061963265"

  strings:
    $s1 = "ToMB)ay" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}