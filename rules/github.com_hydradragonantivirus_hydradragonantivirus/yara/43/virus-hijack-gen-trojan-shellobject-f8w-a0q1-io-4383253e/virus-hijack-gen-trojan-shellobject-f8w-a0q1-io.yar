rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a0q1_io {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64dbd030977752a5757206689c3cce191a826772fe16fb6ec62d4eac714c8984"

  strings:
    $s1 = "aoor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}