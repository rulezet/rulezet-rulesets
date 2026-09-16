rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_293_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_293_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33810b62e77a16972af0f50f9f05835f8d684308c742d3470ba28abd50ff9326"

  strings:
    $s1 = "PUCK:B+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}