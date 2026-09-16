rule Virus_Hijack_Trojan_GenericKDZ_98113_148 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_148.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6d9311f671c9b24b72a0f57e9026293529d3cc05eccd4ade084faac7a9f2a6"

  strings:
    $s1 = "1or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}