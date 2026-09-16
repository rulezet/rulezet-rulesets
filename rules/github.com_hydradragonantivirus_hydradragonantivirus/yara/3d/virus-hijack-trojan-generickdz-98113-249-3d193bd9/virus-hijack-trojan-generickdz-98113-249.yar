rule Virus_Hijack_Trojan_GenericKDZ_98113_249 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_249.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11a2f6305aaef325f9c39016cfde7e7e0272a573868487527ea4b9476a26da05"

  strings:
    $s1 = "@oNiOn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}