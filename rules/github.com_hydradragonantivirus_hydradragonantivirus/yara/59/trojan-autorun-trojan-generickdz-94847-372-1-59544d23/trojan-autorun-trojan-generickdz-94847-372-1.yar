rule Trojan_Autorun_Trojan_GenericKDZ_94847_372_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_372_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff47479c732b398c1250980555b6fd48a6be9318bbc802442207f21bd3bbdcb8"

  strings:
    $s1 = "[fIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}