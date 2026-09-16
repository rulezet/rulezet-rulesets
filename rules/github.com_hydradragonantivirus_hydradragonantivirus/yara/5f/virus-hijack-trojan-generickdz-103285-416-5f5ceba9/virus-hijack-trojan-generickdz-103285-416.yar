rule Virus_Hijack_Trojan_GenericKDZ_103285_416 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_416.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5208fdac9e6da6c3d9d12fb785c35dd729c36a72032e69f9c8628a9657e9785b"

  strings:
    $s1 = "~University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}