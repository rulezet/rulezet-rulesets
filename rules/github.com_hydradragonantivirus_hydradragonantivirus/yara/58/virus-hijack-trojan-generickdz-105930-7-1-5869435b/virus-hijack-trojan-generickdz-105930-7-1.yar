rule Virus_Hijack_Trojan_GenericKDZ_105930_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ea246c83bb5a4e4b6dc42e8b5f7e38c38721ba40506516f08394e34aaed6f6"

  strings:
    $s1 = "J*gRaY*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}