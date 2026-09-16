rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d796256a9b244346ea3c396d7f686846f7454dc04c34018604b6d75ac688434"

  strings:
    $s1 = "7?ROBe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}