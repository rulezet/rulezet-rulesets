rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "941697b5a76c053f388fb083fac9d220783dab1d2a38d47512125324d548fe44"

  strings:
    $s1 = ".opened cache file: %S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}