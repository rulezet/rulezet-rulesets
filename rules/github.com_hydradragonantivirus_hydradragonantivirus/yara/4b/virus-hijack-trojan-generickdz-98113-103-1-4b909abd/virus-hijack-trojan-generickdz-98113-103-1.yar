rule Virus_Hijack_Trojan_GenericKDZ_98113_103_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_103_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c63cc91d4aeed41811660b0356dc8aba14c061fcb101e966c2742c7a56f91bb6"

  strings:
    $s1 = "W`SePS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}