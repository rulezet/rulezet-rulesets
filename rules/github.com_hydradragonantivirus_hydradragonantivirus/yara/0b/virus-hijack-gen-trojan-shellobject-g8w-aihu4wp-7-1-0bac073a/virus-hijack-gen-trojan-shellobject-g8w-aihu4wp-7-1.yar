rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92588987b815f4e57c4085e7ce8c524056cff0969369082228ae4650c2942213"

  strings:
    $s1 = "retro face" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}