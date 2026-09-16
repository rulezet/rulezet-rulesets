rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abcbb175a185260329bd3ede5d5fdd84f3a09501ae123bf2f92a13a84bcb4164"

  strings:
    $s1 = "{Vfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}