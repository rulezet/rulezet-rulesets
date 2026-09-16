rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a8YIsUn_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a8YIsUn_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36df56768822c31ba0763868b9f41b2158ac7a8d0c25e8a84074c54288f2f0e4"

  strings:
    $s1 = "5remainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}