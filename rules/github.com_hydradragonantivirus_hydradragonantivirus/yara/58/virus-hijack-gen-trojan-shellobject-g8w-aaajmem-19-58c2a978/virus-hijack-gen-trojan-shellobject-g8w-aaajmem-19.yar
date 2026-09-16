rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a158dd5a7a05baaced17a0dd04133dfaac061f5d2387db413307d559361d08"

  strings:
    $s1 = "'TWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}