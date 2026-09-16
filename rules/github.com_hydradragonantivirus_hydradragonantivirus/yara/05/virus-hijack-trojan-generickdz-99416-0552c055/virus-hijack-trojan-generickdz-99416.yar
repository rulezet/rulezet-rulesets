rule Virus_Hijack_Trojan_GenericKDZ_99416 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c8a3defaaa6ce06d057dfdeb8fdb5a3678257ba3f5091382e67ed28171465f7"

  strings:
    $s1 = "i~User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}