rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_328_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_328_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cab1c11bb2eb5c328a8f1563a10e843f91e48bc8d817a6bc87544b387b47edd4"

  strings:
    $s1 = "&by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}