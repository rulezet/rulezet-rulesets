rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_539_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_539_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42f2797f290416febfd329b437a610c1189c0dc505df4762f0cbd30393ad78c0"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}