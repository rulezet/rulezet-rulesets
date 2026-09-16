rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_579_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_579_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15e24e853d387cb751aaa10bc19507691a36f8a06a7422df7643995d58542bc8"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii
    $s2 = "G&month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}