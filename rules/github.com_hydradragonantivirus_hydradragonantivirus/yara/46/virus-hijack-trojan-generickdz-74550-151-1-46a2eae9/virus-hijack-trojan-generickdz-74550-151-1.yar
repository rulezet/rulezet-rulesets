rule Virus_Hijack_Trojan_GenericKDZ_74550_151_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_151_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1cc10988697ddcda6230347918d0e3448d26dd063cbfe87b50d8ae828400530"

  strings:
    $s1 = "CoDa%6@G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}