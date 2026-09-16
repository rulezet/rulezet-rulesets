rule Virus_Hijack_Trojan_GenericKDZ_105924_567_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_567_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61dfe5e26389c0aff4aa05525a4261b64b57e1891a20b49d22585ecfb35bf0d"

  strings:
    $s1 = "jefF!ieF" fullword ascii
    $s2 = ":wIME>" fullword ascii
    $s3 = "S%burO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}