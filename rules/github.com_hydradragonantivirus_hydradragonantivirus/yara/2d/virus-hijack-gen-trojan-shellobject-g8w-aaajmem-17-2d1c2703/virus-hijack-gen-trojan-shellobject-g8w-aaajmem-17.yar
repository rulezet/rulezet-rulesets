rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3503feba0aa4148c5856ee09c775bcad65f25445d0425b7a427d11c9fd28a62e"

  strings:
    $s1 = "{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}