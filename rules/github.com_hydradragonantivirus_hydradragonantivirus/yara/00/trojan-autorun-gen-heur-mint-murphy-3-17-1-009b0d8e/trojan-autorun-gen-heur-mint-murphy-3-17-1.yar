rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_17_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9e12c24bb650265134cc6d286a325a67942385f251b54ba0ca147bac8a2936c"

  strings:
    $s1 = "<LAET&>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}