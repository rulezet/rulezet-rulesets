rule Trojan_Autorun_Gen_Variant_Strictor_288194 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Strictor.288194.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9559242d5fa14db235e5eaafe0a34f26b5c025c6f5b22d68b8ca47837f07c4d9"

  strings:
    $s1 = "O!daRK" fullword ascii
    $s2 = "b:fall" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}