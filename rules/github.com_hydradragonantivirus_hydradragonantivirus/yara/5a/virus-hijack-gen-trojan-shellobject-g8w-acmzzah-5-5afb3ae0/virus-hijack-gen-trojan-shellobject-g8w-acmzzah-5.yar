rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da659df31834156a0e37672137ce04ff3eb0aaa2d2b0962ded43ab66b412c494"

  strings:
    $s1 = "a:orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}