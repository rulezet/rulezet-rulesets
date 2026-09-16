rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_302_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_302_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9684f99dc071ff021220b6f497b2399121ecec21fc76eef6f373ed7f735d9b1"

  strings:
    $s1 = "B;hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}