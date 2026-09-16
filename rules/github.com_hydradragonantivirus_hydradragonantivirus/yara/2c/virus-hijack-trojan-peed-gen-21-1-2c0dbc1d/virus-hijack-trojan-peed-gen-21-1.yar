rule Virus_Hijack_Trojan_Peed_Gen_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8ac7e75e5c918afa8c94198f12a3cdfe3df6a41eb3f32aa1ec5b3d2e8285412"

  strings:
    $s1 = "GYtE&Zfs" fullword ascii
    $s2 = "&|`tUke" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}