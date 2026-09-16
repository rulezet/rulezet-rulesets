rule Virus_Hijack_Gen_Trojan_ShellObject_m8X_aW0I0Cd_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8X@aW0I0Cd_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8ecde7bb64b793262a3aa1b346612d9e44784e43327c33625d573aacfbb45f4"

  strings:
    $s1 = "beLA!e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}