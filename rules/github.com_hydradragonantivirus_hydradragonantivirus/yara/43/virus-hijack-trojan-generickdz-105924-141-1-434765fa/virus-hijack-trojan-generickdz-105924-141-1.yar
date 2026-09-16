rule Virus_Hijack_Trojan_GenericKDZ_105924_141_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "411802853411f86201424b9a575c10f363abc1a65b3b4c48e847e7d6aeb46afb"

  strings:
    $s1 = " GOBo P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}