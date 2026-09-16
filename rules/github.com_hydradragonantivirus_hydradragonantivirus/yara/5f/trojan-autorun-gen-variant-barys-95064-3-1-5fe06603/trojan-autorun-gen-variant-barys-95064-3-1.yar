rule Trojan_Autorun_Gen_Variant_Barys_95064_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed07873307fa6067c5adbdd278dc97684ca429c9ba983495cf51baa7a0e214e2"

  strings:
    $s1 = "KNOW*A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}