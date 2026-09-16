rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe7df79a9d6c8c2e59b2596f1c0e0d982352d5ef68152868ba9322cca0f1e23"

  strings:
    $s1 = "LWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}