rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiSalvm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiSalvm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "415a0298fcb6757a557ffbb70d4058d606516bddc5e473d0d6f2b915256da629"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii
    $s2 = ";must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}