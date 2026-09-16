rule Trojan_Autorun_Trojan_GenericKDZ_95768_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95768_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80e90577d0e726b6063881ef591df1ed4da7bfd9e4ceb9ade6385e27710351c2"

  strings:
    $s1 = "6iautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}