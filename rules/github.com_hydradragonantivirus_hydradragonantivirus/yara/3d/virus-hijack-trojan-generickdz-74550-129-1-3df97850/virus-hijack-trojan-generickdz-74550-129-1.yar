rule Virus_Hijack_Trojan_GenericKDZ_74550_129_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_129_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b539378bdc4a45fce61e5dd2e29aad506ec4f9a1b7b6c37010e95d4e904ad6f2"

  strings:
    $s1 = "UW;BlaS" fullword ascii
    $s2 = " doBE;/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}