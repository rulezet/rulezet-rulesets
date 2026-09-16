rule Virus_Hijack_Trojan_GenericKDZ_105930_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8738401e3e9cc34d075965b1158aeb9f92c14a8ac8fc7ecef3ff240b4c82eb19"

  strings:
    $s1 = "POUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}