rule Virus_Hijack_Trojan_GenericKDZ_98113_218 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_218.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7764689c2c931fb3ad62dc08756ace94d6538944d1da252e7bdb1c437f7ae0b4"

  strings:
    $s1 = "qby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}