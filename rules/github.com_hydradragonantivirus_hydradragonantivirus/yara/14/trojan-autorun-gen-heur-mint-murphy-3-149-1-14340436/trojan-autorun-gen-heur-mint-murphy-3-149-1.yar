rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_149_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c5fb93dcd50dabfb69ad66e524e276aa1715354235a6d15ab0cf1c6a55bc65e"

  strings:
    $s1 = "staR]S_g" fullword ascii
    $s2 = "staR]5~bxc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}