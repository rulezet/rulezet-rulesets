rule Virus_Hijack_Trojan_GenericKDZ_98113_368 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_368.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "440ea93a95a7b250e785dcc0e2172745438e9759552357c83fe87685a5b3085e"

  strings:
    $s1 = "M4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}