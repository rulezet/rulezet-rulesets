rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_61_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5a736c5a109ff73e34eadd90843e97f3ce2eac1aee7e511f0b20ff08168175"

  strings:
    $s1 = "Zhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}