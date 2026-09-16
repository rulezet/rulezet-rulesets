rule Trojan_Autorun_Trojan_GenericKD_72517131_115_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_115_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b1b6c5b8a611b560ff6695a6c3b87128ef76ba509091ad920fd4459e744e2ba"

  strings:
    $s1 = "p4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}