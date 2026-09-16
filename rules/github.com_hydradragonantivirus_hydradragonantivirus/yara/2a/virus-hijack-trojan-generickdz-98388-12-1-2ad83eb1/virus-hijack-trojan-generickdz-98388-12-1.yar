rule Virus_Hijack_Trojan_GenericKDZ_98388_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1e64d484019db39d0012578116f0ddcb1fa8d5cfc3628557ee5ba19ab6b2f68"

  strings:
    $s1 = "1:rOpP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}