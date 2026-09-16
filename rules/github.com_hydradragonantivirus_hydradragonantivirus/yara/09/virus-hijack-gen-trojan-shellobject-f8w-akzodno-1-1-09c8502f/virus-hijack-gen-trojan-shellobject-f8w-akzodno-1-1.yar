rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac00fc0a78d7997f9c841b09de0b1f4a9ba87a386b9aa7624d80ca93be6db56e"

  strings:
    $s1 = "return castle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}