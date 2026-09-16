rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb10c0b49efcea1beca5ff0aff5e2d5b0d0ec769d6f0bfe4ebe800216999c4f4"

  strings:
    $s1 = "AWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}