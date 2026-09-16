rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3b9d2b6f459422f6c9a6041b2a8d6488475eaee2618a16bd81484e2ae562d51"

  strings:
    $s1 = "aProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}