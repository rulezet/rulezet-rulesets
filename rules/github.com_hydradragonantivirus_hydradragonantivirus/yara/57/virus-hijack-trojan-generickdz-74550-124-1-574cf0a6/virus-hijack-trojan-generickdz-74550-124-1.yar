rule Virus_Hijack_Trojan_GenericKDZ_74550_124_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "231db7d20cda888098f46795ce52988a5827d207b516d61f780750b58eb45fb3"

  strings:
    $s1 = "b gIBE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}