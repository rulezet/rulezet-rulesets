rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9480e1273de333f7f234d9c64bee47811255835f31396638a699ab61470a48c7"

  strings:
    $s1 = "!ALeE}{P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}