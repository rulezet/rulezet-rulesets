rule Virus_Hijack_Trojan_GenericKDZ_105924_601_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_601_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "981a21f92837668eb1266cdc3b522d82def5f7e8aceb491c5c46c8bca4fafc18"

  strings:
    $s1 = "u\"ArBA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}