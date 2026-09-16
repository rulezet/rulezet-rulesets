rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f51713ace50300ae41c716f3c4fa0fee3ff0fb2daa76631ed3eb4c07489508c"

  strings:
    $s1 = ";dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}