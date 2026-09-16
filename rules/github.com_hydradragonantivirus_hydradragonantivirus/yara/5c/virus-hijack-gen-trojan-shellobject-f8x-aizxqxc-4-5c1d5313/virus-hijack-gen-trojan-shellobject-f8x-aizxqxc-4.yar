rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6092d47fa0e9035154ae5647414225a5e8a5351f26b965fae6cb332284e68dc"

  strings:
    $s1 = "!Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}