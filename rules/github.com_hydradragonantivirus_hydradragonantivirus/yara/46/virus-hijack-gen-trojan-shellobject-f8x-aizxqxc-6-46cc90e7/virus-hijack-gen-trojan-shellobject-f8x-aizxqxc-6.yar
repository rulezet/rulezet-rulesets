rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1a2c69c444c723d40784f436c179989316d7729f0cb9f1a047a2b917b86e5ad"

  strings:
    $s1 = "yProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}