rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "101dcb0ace1beb3edab5174a65efce5ef04d464b72aa6cb9e2c54ff2405a0bba"

  strings:
    $s1 = "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}