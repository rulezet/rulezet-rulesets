rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c38c8e60ff26f5f74898f70d420bf98e4624b90f0624b9603ba4db41cbf14b5"

  strings:
    $s1 = "z2by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}