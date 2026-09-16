rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiSalvm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiSalvm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dab781651244fe1fe398a6aa30b3e160e06f8c3dbc15ca6fa3a5e45cef5fd8b"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii
    $s2 = "\\must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}