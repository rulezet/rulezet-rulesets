rule Virus_Hijack_Trojan_GenericKDZ_94849_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b4a036d4da13a2f62f176a2c22c3562952fe101f2ab2e3a0bd602b57341bc53"

  strings:
    $s1 = "AdoZE*X.V" fullword ascii
    $s2 = "NOLL@'" fullword ascii
    $s3 = "3,boBo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}