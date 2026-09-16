rule Virus_Hijack_Trojan_GenericKDZ_98388_199_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_199_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83c4cd47e9b119d3267b275bd3ceccfc92c99030bf9e708658ea2b4f784d89f1"

  strings:
    $s1 = "STuT&i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}