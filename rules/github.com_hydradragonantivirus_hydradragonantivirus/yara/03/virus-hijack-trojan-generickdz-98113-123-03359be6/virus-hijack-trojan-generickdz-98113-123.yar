rule Virus_Hijack_Trojan_GenericKDZ_98113_123 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_123.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e03126fd93d628d8ed0cdd681e5c1ab20350bfae11a1d7219952af289ce5ecb"

  strings:
    $s1 = "@|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}