rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_a8oUJio_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@a8oUJio_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "676f0b11eb9464e2c5305eeda1c2c0306cf34d82ce88cbb8ff6bf72277815d2b"

  strings:
    $s1 = "P>#gLUT{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}