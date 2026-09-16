rule Virus_Hijack_Trojan_GenericKDZ_79663_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0abc62a4e4250f159cf123f9ec440c5da1bbbc3944f84159011ff1aac663694"

  strings:
    $s1 = "SKEP)CS" fullword ascii
    $s2 = "\"TUbE]t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}