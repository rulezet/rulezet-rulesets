rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6290d0246daa191301c9da3cca62b530dd831dc4e65507aea961cd70cf575c"

  strings:
    $s1 = "gUle&7Trc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}