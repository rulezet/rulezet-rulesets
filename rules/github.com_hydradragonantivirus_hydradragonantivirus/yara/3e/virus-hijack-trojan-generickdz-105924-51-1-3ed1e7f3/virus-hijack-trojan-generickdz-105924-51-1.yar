rule Virus_Hijack_Trojan_GenericKDZ_105924_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57f92994bb796a448e2759e76b5d6ad77af67a9523623bcb08eb4fd22072505a"

  strings:
    $s1 = "SteAn;4" fullword ascii
    $s2 = "k#BEEn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}