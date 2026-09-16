rule Virus_Hijack_Trojan_GenericKDZ_98388_236_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_236_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0f99bb7c0a4d757cc3ebea1598f8e30a0e0f6faacea96660dddc1e01736d5f1"

  strings:
    $s1 = "y)muST" fullword ascii
    $s2 = "n&kNaG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}