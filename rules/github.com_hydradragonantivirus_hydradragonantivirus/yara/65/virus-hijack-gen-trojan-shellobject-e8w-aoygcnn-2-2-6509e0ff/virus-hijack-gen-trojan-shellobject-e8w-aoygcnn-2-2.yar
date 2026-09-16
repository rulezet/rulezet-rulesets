rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0707f70edf85502de6a4aadff89508b43c5cddf54b56393c4bddcc27e5a666"

  strings:
    $s1 = "iP>HuSK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}