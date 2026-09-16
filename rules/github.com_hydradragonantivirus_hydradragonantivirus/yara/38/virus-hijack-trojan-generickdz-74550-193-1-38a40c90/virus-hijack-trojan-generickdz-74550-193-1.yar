rule Virus_Hijack_Trojan_GenericKDZ_74550_193_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_193_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f3c1435adf4497363a14ae06088fcf49354d8b47d197c54cab1eaa93aa2e9b0"

  strings:
    $s1 = "?(beEn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}