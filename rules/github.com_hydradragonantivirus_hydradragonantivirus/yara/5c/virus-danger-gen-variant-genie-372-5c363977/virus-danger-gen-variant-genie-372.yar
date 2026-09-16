rule Virus_Danger_Gen_Variant_Genie_372 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Variant.Genie.372.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "135312cb4872f204cc10ba52507f4a24f002e91f879a143d51b26e58eca6765b"

  strings:
    $s1 = "~:mAck" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}