rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_124_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "425c3825f3f3fd67fa091aca0ca4c25f6904ae6a0d863f7f613580ef870c3eaf"

  strings:
    $s1 = "[America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}