rule Virus_Hijack_Trojan_GenericKDZ_99416_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf311a9e0b52c0cb3292f2e31309af2168dd949436d75787c2d26d72b5cf32e0"

  strings:
    $s1 = "eCUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}