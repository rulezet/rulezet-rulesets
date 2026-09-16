rule Trojan_Autorun_Trojan_GenericKD_72517131_104_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89fe2058c5daf945e0cd6ddfad91c4c94450d775ea84052a1aeb7d9566b361c2"

  strings:
    $s1 = "h4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}