rule Virus_Hijack_Trojan_GenericKDZ_105930_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b64d67ec1fce6d1133d210d30e2a588903d7271aec4e670abd58257abc33f9be"

  strings:
    $s1 = ":f!peCH" fullword ascii
    $s2 = "`eNl,Bulk" fullword ascii
    $s3 = "eveN%," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}