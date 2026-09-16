rule Virus_Hijack_Trojan_GenericKDZ_79663_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b195c0c6fb0f35b4a11e3cf2ec2b0a486e86b408d7fc834753e189a726ed9d50"

  strings:
    $s1 = "Y?SYNe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}