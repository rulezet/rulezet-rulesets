rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0V9N8g {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0V9N8g.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b60a7ea9a0cd12a460304a8a6935c43d709124833e6bc999d63d5c6e8e6f042"

  strings:
    $s1 = "uby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}