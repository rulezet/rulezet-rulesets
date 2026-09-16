rule Virus_Hijack_Trojan_GenericKDZ_74550_60_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce97d7bff082811859c3894e53ea068016eeab530adefd5ccc1d0a1e68aa710c"

  strings:
    $s1 = "Cush&^v" fullword ascii
    $s2 = "$3%CHoky" fullword ascii
    $s3 = "L]s:gAlt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}