rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb73cc11f1568dd542eaf51d88c9a99d42582870390712ce8a7d61002224d7b7"

  strings:
    $s1 = "Dby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}