rule Virus_Hijack_Trojan_GenericKDZ_105924_325_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_325_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85147550b928f991c60775e6f08ce03c149def21cfda4243a58f7015fe7bc9b2"

  strings:
    $s1 = "_a(mArl" fullword ascii
    $s2 = "& ;CHEEk" fullword ascii
    $s3 = "AdaD$9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}