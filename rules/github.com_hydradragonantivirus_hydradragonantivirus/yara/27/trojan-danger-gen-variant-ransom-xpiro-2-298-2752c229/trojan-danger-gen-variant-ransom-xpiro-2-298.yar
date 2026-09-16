rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_298 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_298.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c5a37e2b8310ab2864b96f523798c92a51a3685f7e8096cd3f78b4f3640fafd"

  strings:
    $s1 = "#About Java.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}