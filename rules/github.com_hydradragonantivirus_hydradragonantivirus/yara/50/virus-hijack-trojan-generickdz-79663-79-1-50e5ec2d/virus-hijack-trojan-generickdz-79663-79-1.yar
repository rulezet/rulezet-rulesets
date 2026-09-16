rule Virus_Hijack_Trojan_GenericKDZ_79663_79_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a949d38c4a35c48be9866c31a8f868e0261c66c26db4ea852eedd153e3da3da"

  strings:
    $s1 = "BOZa>X{0}" fullword ascii
    $s2 = "R{ilLy" fullword ascii
    $s3 = "&#VEnd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}