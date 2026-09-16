rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6655405d512dacc8f9727a58440a7d39d27169dde0b6c42342cc9fddab1bd6e9"

  strings:
    $s1 = "Text File, Or Html" fullword wide
    $s2 = "Image Formats" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}