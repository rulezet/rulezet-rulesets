rule Virus_Hijack_Trojan_GenericKDZ_103545_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b35de30f38a1992d56064d29d41eebfca0a641415efe52b6921882ffd2a9bc74"

  strings:
    $s1 = "ci@GUaO" fullword ascii
    $s2 = "REDO)c" fullword ascii
    $s3 = "g}aWaT" fullword ascii
    $s4 = "p?iPIL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}