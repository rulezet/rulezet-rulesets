rule Virus_Hooker_Gen_Variant_Cerbu_142624_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Cerbu.142624_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fa6848e5a9898daa7c1b81c70444d3829f0b767109fd30972d9f4c085cdb558"

  strings:
    $s1 = "`e)mesH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}