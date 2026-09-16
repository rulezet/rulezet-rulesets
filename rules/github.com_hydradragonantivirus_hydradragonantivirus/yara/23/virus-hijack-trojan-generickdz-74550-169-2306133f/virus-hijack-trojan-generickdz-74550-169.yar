rule Virus_Hijack_Trojan_GenericKDZ_74550_169 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_169.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65a272d534095e83981e3b724b2dbf6f981f64fd15fce2729b17802b07b24ed9"

  strings:
    $s1 = "h&feme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}