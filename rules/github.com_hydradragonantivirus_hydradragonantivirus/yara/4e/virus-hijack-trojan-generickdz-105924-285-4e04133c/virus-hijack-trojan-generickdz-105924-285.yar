rule Virus_Hijack_Trojan_GenericKDZ_105924_285 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_285.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2ae5af898a8c6d76947b9d6b65b557ab39343d9f6992ec0f5df1f2dcc3c671e"

  strings:
    $s1 = "a%mAry&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}