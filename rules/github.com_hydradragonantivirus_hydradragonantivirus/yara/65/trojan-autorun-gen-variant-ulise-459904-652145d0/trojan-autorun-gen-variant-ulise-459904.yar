rule Trojan_Autorun_Gen_Variant_Ulise_459904 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ulise.459904.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e6da9a4495d5aaededfddaa155001047e02e9b4eb7d609efb9f78d24f9fd321"

  strings:
    $s1 = "~Visible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "{::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}