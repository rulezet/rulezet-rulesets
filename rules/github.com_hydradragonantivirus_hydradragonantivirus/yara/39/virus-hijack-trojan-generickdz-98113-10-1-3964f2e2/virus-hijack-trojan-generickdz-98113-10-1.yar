rule Virus_Hijack_Trojan_GenericKDZ_98113_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1135a38c92896b5851b636d43a71670063d2f34f99fa4429a9234e22c01a63b"

  strings:
    $s1 = "ulmO'A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}