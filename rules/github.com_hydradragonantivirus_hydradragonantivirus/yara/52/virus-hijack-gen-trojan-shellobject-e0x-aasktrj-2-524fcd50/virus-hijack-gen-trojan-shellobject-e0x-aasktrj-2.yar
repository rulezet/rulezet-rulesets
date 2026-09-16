rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3392b933de47cbbe5909b75fd540f457bb482b30ccb2a4f223178e3d618a6be"

  strings:
    $s1 = ":functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}