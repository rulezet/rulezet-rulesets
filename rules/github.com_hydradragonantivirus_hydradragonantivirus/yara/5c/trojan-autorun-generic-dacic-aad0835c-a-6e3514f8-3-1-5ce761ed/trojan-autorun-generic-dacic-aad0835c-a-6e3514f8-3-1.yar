rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_6E3514F8_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.6E3514F8_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e850f5d21127b5e72b09c133cf8a8201bf3fc12ed1764b931a92896b1c6d2ec"

  strings:
    $s1 = "Cby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}