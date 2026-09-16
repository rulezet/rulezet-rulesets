rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_aKzulAn_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@aKzulAn_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6709868d3ead69e803034185371ef16f88b658a9ff673eea1c0b0073c9aebc0"

  strings:
    $s1 = "U*inRo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}