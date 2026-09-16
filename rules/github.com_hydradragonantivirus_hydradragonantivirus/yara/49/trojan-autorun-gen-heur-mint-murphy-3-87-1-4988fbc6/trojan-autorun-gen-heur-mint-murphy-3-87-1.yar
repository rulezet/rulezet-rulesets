rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_87_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3ce4e1477577278d4bce2a92106e73e892675b5e360090c13c5e42c9a9ae75e"

  strings:
    $s1 = "h&by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}