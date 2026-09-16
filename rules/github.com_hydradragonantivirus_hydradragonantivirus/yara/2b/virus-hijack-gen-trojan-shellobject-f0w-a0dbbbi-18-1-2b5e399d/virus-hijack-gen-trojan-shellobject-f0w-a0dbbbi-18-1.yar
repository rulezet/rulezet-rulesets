rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d308b47a5eb180734306fe03f8bb6afdc2e2ae6be6d1de3aafd2da8c4f531e7"

  strings:
    $s1 = "Supreme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}