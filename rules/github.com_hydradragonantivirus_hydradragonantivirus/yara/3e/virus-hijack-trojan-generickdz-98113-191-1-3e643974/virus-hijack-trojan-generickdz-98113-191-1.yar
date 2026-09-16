rule Virus_Hijack_Trojan_GenericKDZ_98113_191_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_191_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee22eb243a1f407928fa54d44b03c4136d21dd3d9735f826719afffdc14ffae6"

  strings:
    $s1 = "x>]Hilt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}