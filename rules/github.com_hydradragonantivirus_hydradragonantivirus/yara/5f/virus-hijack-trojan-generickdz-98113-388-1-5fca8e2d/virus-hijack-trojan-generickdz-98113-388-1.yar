rule Virus_Hijack_Trojan_GenericKDZ_98113_388_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_388_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f2c433ae9ac1ff1afe7c352ed2ecb4ab87d98dfb2b81f746e97eac2408bbb85"

  strings:
    $s1 = "saLE?D" fullword ascii
    $s2 = "trUn)l" fullword ascii
    $s3 = "k:jIff" fullword ascii
    $s4 = "Q,NAkO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}