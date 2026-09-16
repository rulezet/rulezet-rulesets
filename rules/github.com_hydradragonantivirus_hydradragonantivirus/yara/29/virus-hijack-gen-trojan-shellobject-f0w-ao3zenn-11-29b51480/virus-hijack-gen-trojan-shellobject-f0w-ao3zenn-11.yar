rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f420e16786243e2dc709b008fd5de57f1e45e14ee4cc9ed5bb5a66d04ce7b410"

  strings:
    $s1 = "/kdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}