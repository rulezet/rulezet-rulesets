rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_95_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_95_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e53e0b4c57831214e5691117ac2e30e832975f6331cefbfae1a0928a5bb1c8f0"

  strings:
    $s1 = "activation, see microsoft.com/piracy/activation.mspx. If the licensed computer is connected to theK" fullword ascii
    $s2 = "B. Applicability of AgreementM" fullword ascii
    $s3 = "|you to use the applicable licensed application p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}