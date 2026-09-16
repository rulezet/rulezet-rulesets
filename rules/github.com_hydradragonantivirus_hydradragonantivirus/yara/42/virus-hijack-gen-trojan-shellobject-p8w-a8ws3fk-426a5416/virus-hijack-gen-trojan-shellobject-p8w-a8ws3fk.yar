rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fa5cdf248232cbe66cfb0f67e7bb66f9760f15913061a3e1fe41f5f0e491c9a"

  strings:
    $s1 = "farE{D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}