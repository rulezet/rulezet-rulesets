rule Virus_Hijack_Trojan_GenericKDZ_105924_445_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_445_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6493dea1d3f06b7f23f0c4f0d8ba71839a73369d3811fc9762485cdad82939b"

  strings:
    $s1 = "IDyl!t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}