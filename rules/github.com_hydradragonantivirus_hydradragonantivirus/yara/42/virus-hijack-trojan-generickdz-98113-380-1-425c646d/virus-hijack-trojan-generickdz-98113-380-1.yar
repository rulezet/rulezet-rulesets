rule Virus_Hijack_Trojan_GenericKDZ_98113_380_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_380_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203664928ca23c6456ea74291b03f34c447b052556a8521c2189cf32f1916355"

  strings:
    $s1 = "oSsal]@" fullword ascii
    $s2 = "Marl}E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}