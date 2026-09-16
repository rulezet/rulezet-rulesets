rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_209_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d033025a1be8e846364874a9c6ef43d49667324e290cf9cf4a64c88fd12b96c"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}