rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b53c38accde8c961000000ae78fba0fdc256c569791eaa37c1c735a769f114c"

  strings:
    $s1 = "e)What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}