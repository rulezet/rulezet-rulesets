rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_431 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_431.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8e10e04742cc82d471fa363ca185c00ab52e566f026ad8a77149c4621b5bf32"

  strings:
    $s1 = "Documentation for Desktop Apps.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}