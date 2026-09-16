rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb9cf3eacbafbe472203925772079d885b9e13f7f4488708f4063f0aa6ef1f2"

  strings:
    $s1 = "=What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}