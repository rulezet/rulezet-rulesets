rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7325f91233cdcf2c48f476bd9eef8e923b3504a1bd8c9eaacac51ac2bca8f54"

  strings:
    $s1 = "lProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}