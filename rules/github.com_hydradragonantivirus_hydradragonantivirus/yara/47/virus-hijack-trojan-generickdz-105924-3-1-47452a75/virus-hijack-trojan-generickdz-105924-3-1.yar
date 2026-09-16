rule Virus_Hijack_Trojan_GenericKDZ_105924_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e8483592501ad4d4a6bf5fd9f504419c32a63f45f764f0faaa7a315e2e2e91"

  strings:
    $s1 = ">drUID" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}