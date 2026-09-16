rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f354256107e51d3f4104280bf5b7cd6fcdf1c57642e32cf46aa3ba3e1ee5036"

  strings:
    $s1 = "X~University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}