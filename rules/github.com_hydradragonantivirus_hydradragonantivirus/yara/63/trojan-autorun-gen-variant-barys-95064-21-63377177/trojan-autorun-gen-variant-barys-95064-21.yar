rule Trojan_Autorun_Gen_Variant_Barys_95064_21 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcded290d926fab0cf1951a8f8a3a6cec168e3b73d3427034c023a3d43c94fe3"

  strings:
    $s1 = "r,rIdE" fullword ascii
    $s2 = "nAsh>:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}