rule Virus_Hijack_Trojan_GenericKDZ_98113_81_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c75e89f5b5982b0529f57e32ab71aea3bc817137d2f9646b41e33508ca61233b"

  strings:
    $s1 = "SIKa}M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}