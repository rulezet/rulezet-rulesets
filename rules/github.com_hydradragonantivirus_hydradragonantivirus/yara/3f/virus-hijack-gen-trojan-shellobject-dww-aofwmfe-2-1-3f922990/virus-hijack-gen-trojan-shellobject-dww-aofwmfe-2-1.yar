rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e90dc9b25b715254a2edff5e7424ce2b0578c41340b3fcf2ffdc1bb5e69ebf"

  strings:
    $s1 = "SfaXien hako" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}