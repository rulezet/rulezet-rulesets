rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_a0q1_io_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "536860ff577cff1bd3ad831305e98c6a635b1202231939e2a39743563acac6ef"

  strings:
    $s1 = "dor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}