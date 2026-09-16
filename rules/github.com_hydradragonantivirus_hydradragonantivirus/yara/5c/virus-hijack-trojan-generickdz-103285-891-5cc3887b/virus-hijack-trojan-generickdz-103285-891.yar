rule Virus_Hijack_Trojan_GenericKDZ_103285_891 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_891.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fccb76f6b29e78aeb229fe32c4369405759ed53165c29624b45fcbfd7e2f2567"

  strings:
    $s1 = "r(policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}