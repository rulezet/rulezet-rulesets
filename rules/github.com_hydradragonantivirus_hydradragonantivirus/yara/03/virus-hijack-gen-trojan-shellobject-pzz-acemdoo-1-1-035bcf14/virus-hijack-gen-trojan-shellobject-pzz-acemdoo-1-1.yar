rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b1b5a56c57ad6c08f1f5941dbdd1b51bc21b0ad9b7af46a8f3f1f7b1dffb0f"

  strings:
    $s1 = "^8]wiRL" fullword ascii
    $s2 = "|P&COOP" fullword ascii
    $s3 = "giRT$C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}