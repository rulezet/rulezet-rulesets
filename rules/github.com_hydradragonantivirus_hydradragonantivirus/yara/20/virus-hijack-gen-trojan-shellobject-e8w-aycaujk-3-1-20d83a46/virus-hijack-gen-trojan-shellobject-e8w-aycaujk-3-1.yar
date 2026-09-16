rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "461ee063d3994d3890dc1b0620ab2c57d2c1eeb8ac0224d92185f5e9215f761d"

  strings:
    $s1 = "Unable to read directory" fullword ascii
    $s2 = "SOFTWARE\\YuanZhi\\Recovery Genius" fullword ascii
    $s3 = "SOFTWARE\\GoldenSoft\\Recovery Genius" fullword ascii
    $s4 = "SOFTWARE\\GoldenSoft\\Recovery Genius 21st" fullword ascii
    $s5 = "SOFTWARE\\YuanZhi\\Recovery Genius 21st" fullword ascii
    $s6 = "Current ID: " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}