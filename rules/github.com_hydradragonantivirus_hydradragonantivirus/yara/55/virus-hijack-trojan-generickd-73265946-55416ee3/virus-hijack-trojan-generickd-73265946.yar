rule Virus_Hijack_Trojan_GenericKD_73265946 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKD.73265946.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ae51f7ea2d5d911896ba148cc878a801efc133833c4ea0dddb5f48275509b6b"

  strings:
    $s1 = "Dark EyE Coders" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}