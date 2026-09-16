rule Virus_Hijack_Trojan_GenericKDZ_105924_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b76a9b2faeb5bce3747ffa894edd632c9491083293946d8a4bf6226a31518cbd"

  strings:
    $s1 = "reCk<j7" fullword ascii
    $s2 = "]bUBA{E" fullword ascii
    $s3 = "u`dita" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}