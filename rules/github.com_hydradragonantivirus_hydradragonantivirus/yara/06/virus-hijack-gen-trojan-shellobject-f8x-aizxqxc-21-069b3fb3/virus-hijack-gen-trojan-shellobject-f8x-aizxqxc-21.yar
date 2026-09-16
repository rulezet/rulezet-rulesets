rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6753302f9f523e5e5b35c3586e3687ed6eea71a2d37b2ba59d564e16bdab46d"

  strings:
    $s1 = ";Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}