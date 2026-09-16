rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "979bb01f9efbe47e33da00fc2285beb636d2ae437cecea51625c4c7441cf5e1a"

  strings:
    $s1 = "EWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}