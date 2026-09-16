rule Virus_Hijack_Trojan_GenericKDZ_105924_144_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_144_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faf1197701b532940d050d3961e89f843c8e152f73ace1e257eb7c71c175657f"

  strings:
    $s1 = "<Module>{29C0D229-FFD9-498B-9787-CED2CC41CAC2}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}