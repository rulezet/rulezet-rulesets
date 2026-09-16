rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiSalvm_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiSalvm_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a49120bcb05a1122d0ca850e85a21a80c4029b523a846420bdccc3f70b0c5d1f"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii
    $s2 = ";must be a Qualified Educational User to use software marked as " fullword ascii
    $s3 = "fUNt*+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}