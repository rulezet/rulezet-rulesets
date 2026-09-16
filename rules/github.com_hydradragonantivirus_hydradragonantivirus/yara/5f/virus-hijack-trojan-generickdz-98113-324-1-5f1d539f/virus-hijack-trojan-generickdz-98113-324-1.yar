rule Virus_Hijack_Trojan_GenericKDZ_98113_324_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8d3b248fa62f1756217a8462d456d37b30559393f888d213d349f7f287b37e6"

  strings:
    $s1 = "8&-}SwoB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}