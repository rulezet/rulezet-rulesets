rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70dd70bf79d7724017362a95a1da9fbabd50c3348a9a50281e09ba4082b8e581"

  strings:
    $s1 = "rWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}