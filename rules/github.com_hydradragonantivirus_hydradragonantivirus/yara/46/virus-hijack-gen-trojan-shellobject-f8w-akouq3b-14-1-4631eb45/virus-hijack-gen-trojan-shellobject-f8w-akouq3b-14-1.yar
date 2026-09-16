rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b850afa7127b59a4f8c55d96e007b196eae62962f4219c3b52dabdfde405fd8"

  strings:
    $s1 = "Progra Document" fullword wide
    $s2 = "flash " fullword wide
    $s3 = "SIzY)4" fullword ascii
    $s4 = "0Park Arena, Komaki, Aichi, Japan, 12. vacant WBO" fullword wide
    $s5 = "A kip is a non-SI unit of force. It equals 1000 pounds-force, used primarily by American architects and engineers to measure eng" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}