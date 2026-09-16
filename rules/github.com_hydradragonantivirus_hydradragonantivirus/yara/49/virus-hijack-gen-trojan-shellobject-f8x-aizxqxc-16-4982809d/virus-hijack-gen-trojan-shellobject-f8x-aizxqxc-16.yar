rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7837eb439cad1fe430bca797f988b88cb372c405be7b48ccccb4ed761a2ba530"

  strings:
    $s1 = "oProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}