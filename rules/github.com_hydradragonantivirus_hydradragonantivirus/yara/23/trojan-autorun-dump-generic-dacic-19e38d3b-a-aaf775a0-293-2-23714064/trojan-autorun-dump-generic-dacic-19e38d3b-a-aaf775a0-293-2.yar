rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_293_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_293_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5298f023a0af9c6ae002c8a76645bcf89b1dd180c69a7e45ca43fde4d3b7f86"

  strings:
    $s1 = "mIco)'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}