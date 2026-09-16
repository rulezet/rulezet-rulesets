rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddae1b5fa3a1f3a76371bb236142a78b17671dbbb7f9a9acac7ae6ee8fe642dd"

  strings:
    $s1 = "u)RMJG!MC)/]LAnK" fullword ascii
    $s2 = "o`MALe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}