rule Virus_Hijack_Trojan_GenericKDZ_98113_73_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80ee4cb0a56870ca017d742fcf1e51cd17e5c609f7546c8b24e8bf48b95a7216"

  strings:
    $s1 = "beek@?InM" fullword ascii
    $s2 = "K#beTh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}