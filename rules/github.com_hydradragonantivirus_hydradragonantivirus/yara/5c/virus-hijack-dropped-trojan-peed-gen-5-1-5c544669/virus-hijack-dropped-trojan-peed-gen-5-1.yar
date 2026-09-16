rule Virus_Hijack_Dropped_Trojan_Peed_Gen_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2066d1e7450cc62a8a2807687319a1e8250a0ff255e31054b8877fd9a3d0fab"

  strings:
    $s1 = "SOFTWARE\\YuanZhi\\Recovery Genius" fullword ascii
    $s2 = "SOFTWARE\\GoldenSoft\\Recovery Genius" fullword ascii
    $s3 = "SOFTWARE\\GoldenSoft\\Recovery Genius 21st" fullword ascii
    $s4 = "SOFTWARE\\YuanZhi\\Recovery Genius 21st" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}