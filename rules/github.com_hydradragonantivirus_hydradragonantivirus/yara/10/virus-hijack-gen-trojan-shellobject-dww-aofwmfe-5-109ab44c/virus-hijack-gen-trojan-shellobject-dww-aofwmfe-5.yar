rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "308e770b92abc7790274b87aef0f94fd24e04396a7eebf236ea4211eeddb4d44"

  strings:
    $s1 = "\"posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}