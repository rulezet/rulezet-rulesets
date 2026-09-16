rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c6d91575a9a158e0b908d29ce624596f0420af960fa88bb124d1e01c2a58d6"

  strings:
    $s1 = "4Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}