rule Virus_Hijack_Trojan_EmotetU_Gen_mO0_hmDF4Qci {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.mO0@hmDF4Qci.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a237bbbccb1aed370eddddc8c989c2968143374c69d829b23cf6e5ad31421508"

  strings:
    $s1 = "prepenial" fullword wide
    $s2 = "mooter" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}