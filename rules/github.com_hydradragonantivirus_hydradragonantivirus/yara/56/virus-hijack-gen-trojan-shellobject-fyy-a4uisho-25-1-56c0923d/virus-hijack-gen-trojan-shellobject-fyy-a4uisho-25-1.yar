rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9656fce13d0f71657b2981b0af2d6533485cefc9f6e34e41d2b267ab773fc617"

  strings:
    $s1 = "EboE Xk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}