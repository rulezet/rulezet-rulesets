rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_339_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_339_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff90a208a6895c85380d4e104366c8b6bca7ca5fe3c54a76a8eab071faabc94"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii
    $s2 = "#month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}