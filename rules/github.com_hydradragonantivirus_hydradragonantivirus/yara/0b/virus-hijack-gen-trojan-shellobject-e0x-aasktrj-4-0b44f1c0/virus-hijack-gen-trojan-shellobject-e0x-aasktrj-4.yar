rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e30170d1c0ceeda5b44cf49d80a903e69e7c91dd4fc4c87c5091e6b3a83a120"

  strings:
    $s1 = "Ifunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}