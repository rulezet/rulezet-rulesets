rule Virus_Hijack_Trojan_GenericKDZ_105930_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78112464f226da5190e91556e1f5f98ee97aa40a6d7261ec97cda004487b599e"

  strings:
    $s1 = ":>ToRc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}