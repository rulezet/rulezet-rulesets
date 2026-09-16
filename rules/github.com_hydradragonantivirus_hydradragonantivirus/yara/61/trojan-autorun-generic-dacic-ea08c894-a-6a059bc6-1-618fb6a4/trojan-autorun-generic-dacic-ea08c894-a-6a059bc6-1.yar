rule Trojan_Autorun_Generic_Dacic_EA08C894_A_6A059BC6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.EA08C894.A.6A059BC6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7943cee0268be0fa976761f1e886e4967bcbe7849afe3821ca4a7314023d5d36"

  strings:
    $s1 = "Pobs'I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}