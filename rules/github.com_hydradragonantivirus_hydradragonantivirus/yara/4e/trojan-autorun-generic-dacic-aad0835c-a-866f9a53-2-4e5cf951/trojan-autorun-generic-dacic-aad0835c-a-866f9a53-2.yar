rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_866F9A53_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.866F9A53_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdeaf2e772cc6033d795b0c39b5eb52b01769f3d8ebbc11597684810702b773c"

  strings:
    $s1 = "J_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}