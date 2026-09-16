rule Virus_Hijack_Gen_Variant_Dridex_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Dridex.5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c789e11da49c5466957c59fa6de5b2b4dabf3f360fb8899b262e40c4247f21b5"

  strings:
    $s1 = "WebToolBar component" fullword wide
    $s2 = "  is registered trademark of Kaspersky Lab ZAO." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}