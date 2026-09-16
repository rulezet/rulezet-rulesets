rule Virus_Hijack_Trojan_GenericKDZ_99416_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9d79e29545ab20f6a602d2d6e2b897a0e57666367c47acba98bd52d0d717"

  strings:
    $s1 = "kCUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}