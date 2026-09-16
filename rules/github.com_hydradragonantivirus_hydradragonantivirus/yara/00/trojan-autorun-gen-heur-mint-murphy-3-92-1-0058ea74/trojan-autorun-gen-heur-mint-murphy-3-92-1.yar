rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_92_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "836c3018a1597db1318d15d8d17fb9b6c96a36522a775e94f3de91af73e640b5"

  strings:
    $s1 = ":Aby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}