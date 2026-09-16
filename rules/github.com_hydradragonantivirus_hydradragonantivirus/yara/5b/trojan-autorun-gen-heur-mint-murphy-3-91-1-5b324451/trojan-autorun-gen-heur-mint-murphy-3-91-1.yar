rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_91_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7397fd2b1e6e2328eb7406ac3320e6404400ee63fff9a08a35e1e51981359d70"

  strings:
    $s1 = "!4or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}