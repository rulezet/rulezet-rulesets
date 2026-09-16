rule Virus_Hijack_Trojan_GenericKDZ_98388_152_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0a04553c48c1e41386bc4703f1cc49866e08a30d88bc58ab0c4cd23315b6ea7"

  strings:
    $s1 = "L`JaCK" fullword ascii
    $s2 = "&<\\jw*yelm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}