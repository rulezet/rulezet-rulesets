rule Virus_Hijack_Trojan_GenericKDZ_98113_219 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_219.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b99a8b3011a554799c7e9da07a88fcb2427c70872873202f8d1107d6b0bef202"

  strings:
    $s1 = "8#hYke Oq|9^$|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}