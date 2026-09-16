rule Virus_Hijack_Trojan_GenericKDZ_105924_352_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_352_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e080fd4b934c881a08874dff59707d5a7489122b3371d735b2c15d7245186cc"

  strings:
    $s1 = "Fyke'}'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}