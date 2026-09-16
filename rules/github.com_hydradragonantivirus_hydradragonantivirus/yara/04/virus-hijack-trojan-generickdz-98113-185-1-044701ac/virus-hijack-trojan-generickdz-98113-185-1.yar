rule Virus_Hijack_Trojan_GenericKDZ_98113_185_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4908319ccce7dab9e838626dec28877b83b8a5c625f154e23730b448c737ea8e"

  strings:
    $s1 = "CHEW><" fullword ascii
    $s2 = "o\\<GUSh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}