rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_141_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1821131b122dae2b2793b48fab45994beacc9bf0272bd9ffd99926df57e08bde"

  strings:
    $s1 = "E<America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}