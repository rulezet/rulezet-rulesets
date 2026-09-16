rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_a0kuefc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@a0kuefc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f1fb02448c5517fe7f4124523a615e4e735ce48b616192093edee530e50a447"

  strings:
    $s1 = "Vvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}