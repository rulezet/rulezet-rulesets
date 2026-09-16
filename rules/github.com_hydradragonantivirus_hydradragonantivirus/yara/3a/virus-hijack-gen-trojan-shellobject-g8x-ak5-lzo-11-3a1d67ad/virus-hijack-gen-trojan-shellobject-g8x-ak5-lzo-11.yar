rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22976332452b0352f28431bad254cfe06323f9456645f27d95b70958683f6219"

  strings:
    $s1 = "lUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}