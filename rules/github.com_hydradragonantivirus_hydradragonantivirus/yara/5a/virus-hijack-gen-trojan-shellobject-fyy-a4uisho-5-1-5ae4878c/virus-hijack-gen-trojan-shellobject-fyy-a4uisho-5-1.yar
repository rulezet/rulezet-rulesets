rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faecdf9914fc313c2857fd12cb477f4c478386828ba2a3567da52a98be1e1cb9"

  strings:
    $s1 = "EboE Xk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}