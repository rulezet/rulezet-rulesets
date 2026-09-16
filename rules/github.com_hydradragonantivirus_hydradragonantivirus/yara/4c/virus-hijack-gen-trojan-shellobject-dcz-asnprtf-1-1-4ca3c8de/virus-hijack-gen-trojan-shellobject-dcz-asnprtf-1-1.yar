rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb3ec111972c0fa3c642dbb9aff3cbb20376dd74a3540d137c5d35fc3407adc7"

  strings:
    $s1 = "o&lodE" fullword ascii
    $s2 = "m*RYND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}