rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_348_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_348_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9accbcca86fb9ec2b1f25f6c8ea977635d2276dd496b0edc132a259676f16992"

  strings:
    $s1 = "_9by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}