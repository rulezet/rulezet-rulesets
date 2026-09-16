rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19c40a439c46f9d30222959f65062c007d3cacd4dad76df7f4d62889203e42ad"

  strings:
    $s1 = "K-by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}