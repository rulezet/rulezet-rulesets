rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "417df76c4a4ec7ce2d33468c67cd1632c3e91a4e5f687cd9cae4661b8c1dc1af"

  strings:
    $s1 = "=by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}