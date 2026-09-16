rule Trojan_Autorun_Gen_Trojan_Backdoor2_NmZbaaK8fvob_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.NmZbaaK8fvob_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bbb41ed9331489e87ffe1f1ea6852523d91d6726961a76ed9ef2c906cd7eb40"

  strings:
    $s1 = "g4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}