rule Virus_Hijack_Trojan_GenericKDZ_105924_125_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_125_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e13938ae23cbd938a1ed43970f788f8f56ac5176556367ed4bf075ae5aa97e6"

  strings:
    $s1 = "Ns:heaF}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}