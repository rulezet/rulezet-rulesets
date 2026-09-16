rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9075d6818cb9e8ee092c06fc74464093453143eef454c5bdbb68e88f57b0d90e"

  strings:
    $s1 = "dMicrosoft National Language Support Downlevel API" fullword wide
    $s2 = "`W@pEED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}