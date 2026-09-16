rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc058d2b776704bec5bca4f555742258a2747255117955ca3a8524a92696f3a4"

  strings:
    $s1 = "LECH&/" fullword ascii
    $s2 = "b I*MAki," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}