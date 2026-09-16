rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf5198feaaeced150d69aa79135f95048e05d7b865891d294d17886a8e20fe8c"

  strings:
    $s1 = "@Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}