rule Virus_Hijack_Trojan_GenericKDZ_98113_385_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_385_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6358701121b682d5d7eec0eb501fad129a3c28b9c235ad973183befdbaa0e4a"

  strings:
    $s1 = "cw~<BOok?" fullword ascii
    $s2 = "cliT&T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}