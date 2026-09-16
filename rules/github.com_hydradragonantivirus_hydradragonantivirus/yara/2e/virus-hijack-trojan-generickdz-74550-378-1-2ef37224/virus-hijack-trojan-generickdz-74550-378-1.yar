rule Virus_Hijack_Trojan_GenericKDZ_74550_378_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_378_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55bd11a549e657cc2ebd36258d3510ff89900a20bb088aac8335456baf4af95d"

  strings:
    $s1 = "vEIl':l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}