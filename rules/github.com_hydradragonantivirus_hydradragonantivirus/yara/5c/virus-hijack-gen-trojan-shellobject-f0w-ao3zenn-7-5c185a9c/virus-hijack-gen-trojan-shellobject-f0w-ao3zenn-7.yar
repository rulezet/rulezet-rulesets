rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09d829920aa06dc66e5722f874e9e107141153fb47863ac6a62d2906260ab65f"

  strings:
    $s1 = "<$dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}