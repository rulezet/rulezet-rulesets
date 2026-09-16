rule Virus_Hijack_Gen_Variant_Dridex_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Dridex.5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "557dd6d1bbc465232aa07487d789f1853409f69f58bb3c68e9358896f5800dcf"

  strings:
    $s1 = "WebToolBar component" fullword wide
    $s2 = "  is registered trademark of Kaspersky Lab ZAO." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}