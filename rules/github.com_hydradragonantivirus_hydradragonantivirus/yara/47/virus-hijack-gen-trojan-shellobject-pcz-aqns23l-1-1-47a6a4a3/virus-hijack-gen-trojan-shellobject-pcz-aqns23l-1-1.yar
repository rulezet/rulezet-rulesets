rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80f3f195767c80058b8afb7fa334de164bb010b4ab797a8394fa3c1b7a51007a"

  strings:
    $s1 = "X,TeST" fullword ascii
    $s2 = "NoUS[?" fullword ascii
    $s3 = "whiT(8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}