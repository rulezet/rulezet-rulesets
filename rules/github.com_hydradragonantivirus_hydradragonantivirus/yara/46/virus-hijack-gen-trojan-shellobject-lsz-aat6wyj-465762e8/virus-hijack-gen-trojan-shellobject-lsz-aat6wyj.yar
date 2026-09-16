rule Virus_Hijack_Gen_Trojan_ShellObject_lSZ_aaT6Wyj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lSZ@aaT6Wyj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dfd5e04579b31d4674a841cf54cd653bb226cc159399ae6074f3fb26f9905b5"

  strings:
    $s1 = "4whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}