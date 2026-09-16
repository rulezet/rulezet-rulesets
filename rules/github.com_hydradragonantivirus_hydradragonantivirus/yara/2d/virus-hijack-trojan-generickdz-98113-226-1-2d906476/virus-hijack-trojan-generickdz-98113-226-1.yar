rule Virus_Hijack_Trojan_GenericKDZ_98113_226_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_226_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f35ad9a67e8302252d04fe05c329365f66ea5fe741f305f0b8cb0af0112ba7a"

  strings:
    $s1 = "lowY:BJ" fullword ascii
    $s2 = "?@afAr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}