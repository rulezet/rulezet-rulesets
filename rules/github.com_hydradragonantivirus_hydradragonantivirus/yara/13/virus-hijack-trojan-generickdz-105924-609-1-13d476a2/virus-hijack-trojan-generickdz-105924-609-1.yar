rule Virus_Hijack_Trojan_GenericKDZ_105924_609_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_609_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c33d91d00c1b48edf7ed480014a1784d6917ab35ae1d510fbbefa5796a9055"

  strings:
    $s1 = ">-kdJ{When" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}