rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_62_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0484e2b2a9b8c25d7fbc445ca5d0f36f34366c94c877a0c827b710a858700f8"

  strings:
    $s1 = "{Phundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}