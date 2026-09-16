rule Trojan_Autorun_Gen_Variant_Barys_95064 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d3e3c38ecaf09f964190c87ce30f1c0fce84e120f3626066c4a3b0374e22cde"

  strings:
    $s1 = "maaM@g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}