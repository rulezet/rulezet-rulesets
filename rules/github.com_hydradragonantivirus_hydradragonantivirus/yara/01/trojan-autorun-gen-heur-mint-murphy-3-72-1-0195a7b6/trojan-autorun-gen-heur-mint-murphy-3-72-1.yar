rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_72_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97fbabe33deaddfb0c86897285fb605fc3d54556d4c60f277ada206f06b3c0eb"

  strings:
    $s1 = "I4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}