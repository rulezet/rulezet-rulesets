rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_130_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd981bb790187b2926eaf1757841d611b4bc6603fc751e9fa27a4c2639ba8f53"

  strings:
    $s1 = "cvAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}