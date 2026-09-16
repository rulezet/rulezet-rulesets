rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b8acb13e52f82ff3ad3782b7ac5c2646ef7e9f213ebc03e0359f49057d7a155"

  strings:
    $s1 = "^`by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}