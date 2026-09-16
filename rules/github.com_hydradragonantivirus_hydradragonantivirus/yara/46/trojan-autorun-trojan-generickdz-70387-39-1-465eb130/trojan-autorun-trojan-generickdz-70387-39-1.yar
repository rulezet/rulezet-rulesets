rule Trojan_Autorun_Trojan_GenericKDZ_70387_39_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.70387_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2c09dc8aa82a7f7eaebfb6a5ad8265eabb8cb7cd14560150310f0279dda6da8"

  strings:
    $s1 = " :YArR*A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}