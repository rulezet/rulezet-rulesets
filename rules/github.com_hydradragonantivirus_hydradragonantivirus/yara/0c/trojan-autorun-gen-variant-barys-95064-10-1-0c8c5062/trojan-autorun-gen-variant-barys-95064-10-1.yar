rule Trojan_Autorun_Gen_Variant_Barys_95064_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e272341f3ac30e409faefc205037875f95208bf3a45dfe8212b21fac4ee93c49"

  strings:
    $s1 = "Hosted Named User: is defined as an individual authorized by " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}