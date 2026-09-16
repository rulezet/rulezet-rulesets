rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6aa9395ac93bc3ef0c666a36dd0b8996dee3f7d19b3ed927ca24d483f34150a9"

  strings:
    $s1 = "Monoecism" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}