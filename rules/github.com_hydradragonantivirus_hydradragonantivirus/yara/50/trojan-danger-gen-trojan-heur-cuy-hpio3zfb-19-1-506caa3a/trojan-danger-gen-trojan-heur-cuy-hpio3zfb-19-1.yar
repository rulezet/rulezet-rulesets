rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4725ee909cb7f9ff9e0902add92abc8d44bcfab5ebedc1a76e2d89c6aa3e4425"

  strings:
    $s1 = "]fthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}