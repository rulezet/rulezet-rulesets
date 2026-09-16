rule Virus_Hijack_Gen_Trojan_ShellObject_GuZ_aiy413e_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GuZ@aiy413e_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f2091a496ec55e87da5942758aeb7e2c674ad4443b8d71b2b2a3ac93fe36444"

  strings:
    $s1 = "Stannous" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}