rule Virus_Hijack_Trojan_GenericKDZ_105924_335_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_335_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba418273d8d1ae7ce33c5cdfc786099976717ca8639afd2127a599bb07f92cc7"

  strings:
    $s1 = "U DURe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}