rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e70a720f3576c141bac6693070be0c414bdad5d16961864e4540ed6804d802ac"

  strings:
    $s1 = "<University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}