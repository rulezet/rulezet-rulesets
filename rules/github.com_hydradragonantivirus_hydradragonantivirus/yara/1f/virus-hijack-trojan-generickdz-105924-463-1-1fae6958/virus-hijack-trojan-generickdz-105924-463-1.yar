rule Virus_Hijack_Trojan_GenericKDZ_105924_463_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_463_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8a55aa6ab1d2d07c86d3b4c8a20d4e68d43582f00c08ba15e8673f1817c2e22"

  strings:
    $s1 = "CRUs<]" fullword ascii
    $s2 = "|$Hint$" fullword ascii
    $s3 = "JMail%>@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}