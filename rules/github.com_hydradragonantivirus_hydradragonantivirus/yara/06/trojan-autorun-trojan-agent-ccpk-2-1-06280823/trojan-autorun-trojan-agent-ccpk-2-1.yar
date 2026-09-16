rule Trojan_Autorun_Trojan_Agent_CCPK_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Agent.CCPK_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d46342a7c8fd8e635180b2ca6cd701b9a0ac91bf7b65db3a405a6ca8a5908cb"

  strings:
    $s1 = "rH4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}