rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b156fcf564bac41dda45199f707b7d4e92419e881347bebaf3dadbc9f3946615"

  strings:
    $s1 = "kProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}