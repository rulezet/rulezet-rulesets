rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_360_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_360_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0af3653b86c2a54b6cad9f0b7c8a626c0ac60f30ec2b10d64d3a7cc7d025853"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}