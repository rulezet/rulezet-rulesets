rule Virus_Hijack_Trojan_GenericKDZ_98388_149_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ab2528540a45ff76aa4b75e03255c31532cbbb69bc96b852de11d7e83e72057"

  strings:
    $s1 = "{z!BUlL?" fullword ascii
    $s2 = ")O\"prUT" fullword ascii
    $s3 = "rusE$K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}