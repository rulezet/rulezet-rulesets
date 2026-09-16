rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_1FF1C07C_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.1FF1C07C_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ca320101717e50d407d2989bd59b3dcec1ce04c014113cf59dd56bc4b7bf"

  strings:
    $s1 = "Z!KYAr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}