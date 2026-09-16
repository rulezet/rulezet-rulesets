rule Trojan_Autorun_Trojan_GenericKD_72517131_72_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cad0a8625d5d8230b088e7416e69ad15d4ba9767b11d3b5fcf69e8f6589f443"

  strings:
    $s1 = "ML4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}