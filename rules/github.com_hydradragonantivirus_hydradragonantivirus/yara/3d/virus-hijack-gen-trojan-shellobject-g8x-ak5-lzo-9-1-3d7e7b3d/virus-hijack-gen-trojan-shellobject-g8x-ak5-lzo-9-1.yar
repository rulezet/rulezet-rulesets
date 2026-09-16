rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07bb211b113982ff0a3de5e07903ace971b36bc8c1c9525a0e42cf8d001d1d4c"

  strings:
    $s1 = "Vocally" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}