rule Virus_Hijack_Trojan_EmotetU_Gen_m01_hGo8vcoi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.m01@hGo8vcoi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c0075223f8bc1a218dfdd069441904a0a2ac2f46783a8755c939025b0b7974"

  strings:
    $s1 = "frownful" fullword wide
    $s2 = "conservant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}