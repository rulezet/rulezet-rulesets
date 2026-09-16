rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_324_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97926206e05a5f92400683e7c8605c01f01474603ce06cf16bf0124cc120bc0b"

  strings:
    $s1 = "\\or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}