rule Virus_Hijack_Trojan_GenericKDZ_105924_116 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_116.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "781abd450cfeaca46e3b8e2491441cf77897782d96b48698bcef07e79451a268"

  strings:
    $s1 = "n(SpOT" fullword ascii
    $s2 = "3>SpAt" fullword ascii
    $s3 = "R,SpAt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}