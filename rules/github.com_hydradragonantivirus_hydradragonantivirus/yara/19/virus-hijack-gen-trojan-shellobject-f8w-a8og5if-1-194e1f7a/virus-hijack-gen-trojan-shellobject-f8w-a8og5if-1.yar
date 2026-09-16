rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25c7162aa7333cf91f47739b4ad7364025cd815adab9e8f49376593cff7cf004"

  strings:
    $s1 = "Wby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}