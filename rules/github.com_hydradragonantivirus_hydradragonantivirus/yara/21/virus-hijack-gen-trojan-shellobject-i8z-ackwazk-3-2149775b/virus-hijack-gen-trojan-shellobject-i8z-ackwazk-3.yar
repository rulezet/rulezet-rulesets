rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da3d6edd3a570e0d671d0b501c2a64b717675eec9449baf17d6c2a5429aafc61"

  strings:
    $s1 = ":by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}