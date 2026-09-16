rule Virus_Hijack_Trojan_GenericKDZ_105924_416_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_416_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe254faec32a935c736a412a02b3dc3c4b0305f2b4ff9216f663962b84ac5d32"

  strings:
    $s1 = "a%aPSE" fullword ascii
    $s2 = "X`RAfF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}