rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfa1e11387b6e46603c084ded640a2caf3fcda2a6b0f6dd193be35f7d64ec1d2"

  strings:
    $s1 = "Supreme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}