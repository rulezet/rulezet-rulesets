rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_aaT6Wyj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@aaT6Wyj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d250c54e4b900d9cd2d70822c6365e7f71b7ee15dda4b031e65c763c0008fcd"

  strings:
    $s1 = "^Awhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}