rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e90a0d00fe9ceff0a8e3b44e9db75e1c43bfe06dac65385bb2f2f69e31b3909"

  strings:
    $s1 = "KERN`L32.d" fullword ascii
    $s2 = "Copyright  DhustTrers" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}