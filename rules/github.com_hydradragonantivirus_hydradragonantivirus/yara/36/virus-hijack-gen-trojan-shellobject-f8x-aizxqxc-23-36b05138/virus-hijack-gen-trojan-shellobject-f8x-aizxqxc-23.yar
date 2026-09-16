rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28a15258aa363bec1782133d4ceb861365b39055993aa69021a62d557acc1372"

  strings:
    $s1 = "GPProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}