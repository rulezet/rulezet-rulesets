rule Virus_Hijack_Trojan_GenericKDZ_98113_143_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_143_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe065f8ca22b3aa2ad6917739d74d969d75729ee2b9bd9f42e33dd38b4af7d1"

  strings:
    $s1 = "Time Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}