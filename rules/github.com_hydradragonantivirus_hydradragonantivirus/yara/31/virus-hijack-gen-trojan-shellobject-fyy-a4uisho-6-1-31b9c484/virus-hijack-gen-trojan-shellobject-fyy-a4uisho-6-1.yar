rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f11cc9c5903e21ad2624e120b5d0325ddb145b6e9cac1da9e4efcd8f0722de2"

  strings:
    $s1 = "EboE Xk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}