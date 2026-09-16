rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_23_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fe995b416f681c00a23591cc5581db40da54747a87da1290a23e646e2ff32d3"

  strings:
    $s1 = "miAS?@7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}