rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43309df5a7657c0c472a110def2cc097d65081075cc33358a20c197c3a1ab967"

  strings:
    $s1 = "S'or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}