rule Virus_Hijack_Trojan_GenericKDZ_74550_379_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_379_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f735b562f86dba4b2a10bfb79c851f024130a8ee7ba48272ea1b9722c523e686"

  strings:
    $s1 = "]SLoNk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}