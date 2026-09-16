rule Virus_Hijack_Trojan_GenericKDZ_74550_170_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_170_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bca5b8789b0d1bfac3515e81360849930cf7b9a8f0477f561d09b928bb046ee"

  strings:
    $s1 = ";hARk " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}