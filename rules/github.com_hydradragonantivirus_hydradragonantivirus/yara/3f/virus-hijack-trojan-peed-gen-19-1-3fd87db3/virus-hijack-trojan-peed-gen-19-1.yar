rule Virus_Hijack_Trojan_Peed_Gen_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37b52231ff5b2d115091f3f83d85298a1038b245011030d79ae415070c096bbc"

  strings:
    $s1 = "{ ,ephA!" fullword ascii
    $s2 = "GeLd#p8J" fullword ascii
    $s3 = "THOn{w" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}