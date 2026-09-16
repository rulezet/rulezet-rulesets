rule Virus_Hijack_Trojan_GenericKDZ_74550_105_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_105_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7add1e9ae787e987c57843a941045e72ab9a882569990e64ac4e892d074ee097"

  strings:
    $s1 = "=>sIKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}