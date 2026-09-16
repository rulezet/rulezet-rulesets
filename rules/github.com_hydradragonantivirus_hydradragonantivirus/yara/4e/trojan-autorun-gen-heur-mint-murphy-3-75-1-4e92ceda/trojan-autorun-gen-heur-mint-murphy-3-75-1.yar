rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebb3dad94819c97cec42e285db1fab558f386d451152a8b74231bf1cb7bd383a"

  strings:
    $s1 = "ZRby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}