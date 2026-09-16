rule Virus_Hijack_Trojan_GenericKDZ_103285_624_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_624_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82aa561d66ce60b306ceda8e04e80d02932a5f85cc70721fb41691a74c03bede"

  strings:
    $s1 = ".IEC 61966-2.1 Defaul= RGB colour space - sRGB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}