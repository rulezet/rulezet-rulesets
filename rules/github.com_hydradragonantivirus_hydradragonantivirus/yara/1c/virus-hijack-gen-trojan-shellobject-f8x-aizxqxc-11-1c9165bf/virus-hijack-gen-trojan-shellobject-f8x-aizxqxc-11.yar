rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4e9327f21c85978c74620dfdef85fb8b367fbbc29c86cff195e1a55dc7ed059"

  strings:
    $s1 = "T`Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}