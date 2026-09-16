rule Virus_Hijack_Trojan_GenericKDZ_105924_424_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_424_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf5f7a3ab896686a9dc01ce38845fe4bef5815d08d02adcc2f2a989dd1c5a47"

  strings:
    $s1 = "!kipE&<" fullword ascii
    $s2 = "aNAn]M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}