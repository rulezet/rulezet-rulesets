rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_258_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_258_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc207b29b40540f34478fa8e22243d8882c94c47bb5e307989b6b018198dd2a4"

  strings:
    $s1 = "eDDy)u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}