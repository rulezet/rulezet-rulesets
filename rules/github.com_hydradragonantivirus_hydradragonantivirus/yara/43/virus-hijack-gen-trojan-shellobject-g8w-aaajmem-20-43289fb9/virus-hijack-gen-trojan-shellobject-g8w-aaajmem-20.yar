rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdbcda851199753b6d00cce35ea350a4746158c42fd8fcea0b42b6e14b3ca0d6"

  strings:
    $s1 = "KWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}