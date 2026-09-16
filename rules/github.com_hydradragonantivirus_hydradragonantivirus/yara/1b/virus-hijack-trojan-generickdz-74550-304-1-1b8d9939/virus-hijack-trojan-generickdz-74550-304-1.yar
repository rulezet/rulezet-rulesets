rule Virus_Hijack_Trojan_GenericKDZ_74550_304_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_304_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90fc1b1272674e3ba217109380cfce13cb8eee887703aeba3a8a9d428204df05"

  strings:
    $s1 = "a)TyMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}