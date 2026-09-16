rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_327_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_327_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2cba6f706f8f8df9813fc7000d6306a22c2606dc3cba674030108a47fc2f9b2"

  strings:
    $s1 = "%by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}