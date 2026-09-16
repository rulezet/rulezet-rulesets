rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b5f0551f05e7f330b69a4e4c386a76d6b2d32dde2b06253898319f84ca1380"

  strings:
    $s1 = "*Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}