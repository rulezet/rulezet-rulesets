rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1e6337cbabe6a415fd37cce3cde9edad116ac030e85f386f08f0db433dfc140"

  strings:
    $s1 = "^What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}