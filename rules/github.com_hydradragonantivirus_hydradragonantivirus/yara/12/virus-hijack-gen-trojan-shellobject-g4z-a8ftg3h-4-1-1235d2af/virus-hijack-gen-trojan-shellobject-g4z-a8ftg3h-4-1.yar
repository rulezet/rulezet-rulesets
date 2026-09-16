rule Virus_Hijack_Gen_Trojan_ShellObject_g4Z_a8fTg3h_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Z@a8fTg3h_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0656865aad795171871aadf9dd633d98f6837bac78b9a3b1987790468ab45a13"

  strings:
    $s1 = "hubb(]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}