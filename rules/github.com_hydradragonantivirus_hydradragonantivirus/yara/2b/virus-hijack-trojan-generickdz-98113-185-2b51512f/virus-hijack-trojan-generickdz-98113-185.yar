rule Virus_Hijack_Trojan_GenericKDZ_98113_185 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_185.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b59d4a29e479a2d0a80b90914b54334bfc14ae7633a5ba35152bac80c9378ba"

  strings:
    $s1 = "Nby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}