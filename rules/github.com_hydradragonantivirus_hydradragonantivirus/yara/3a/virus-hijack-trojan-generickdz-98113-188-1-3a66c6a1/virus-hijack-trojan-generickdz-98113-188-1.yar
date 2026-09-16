rule Virus_Hijack_Trojan_GenericKDZ_98113_188_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1710438df4a59090cabc39b98686466a9dcc9f5a03d6daadeb7bc6dfd51be9d9"

  strings:
    $s1 = "FOil[q;Y" fullword ascii
    $s2 = "q$gIrd" fullword ascii
    $s3 = "r<SinH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}