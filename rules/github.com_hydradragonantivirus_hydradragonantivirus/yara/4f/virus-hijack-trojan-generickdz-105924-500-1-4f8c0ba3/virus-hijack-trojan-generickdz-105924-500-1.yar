rule Virus_Hijack_Trojan_GenericKDZ_105924_500_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_500_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d87b0b4d0d1a5f00f612328655ba54ba9964054d577ac3d08951906b0adbd27b"

  strings:
    $s1 = "(>sExY`" fullword ascii
    $s2 = "*DAmA{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}