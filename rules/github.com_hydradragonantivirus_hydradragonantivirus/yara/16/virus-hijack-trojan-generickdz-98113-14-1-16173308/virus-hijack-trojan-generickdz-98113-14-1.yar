rule Virus_Hijack_Trojan_GenericKDZ_98113_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f63d763b4c9867c12cfb63718eeefc166769ab0f11be0e3a6c3634564e65798e"

  strings:
    $s1 = "LESt<Y3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}