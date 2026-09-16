rule Virus_Hijack_Trojan_GenericKDZ_103285_443 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_443.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be6ee1289b62e63ee586d1818ad668c22a8b49553dd5ab518a4cc7593f6e3346"

  strings:
    $s1 = "Gremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}