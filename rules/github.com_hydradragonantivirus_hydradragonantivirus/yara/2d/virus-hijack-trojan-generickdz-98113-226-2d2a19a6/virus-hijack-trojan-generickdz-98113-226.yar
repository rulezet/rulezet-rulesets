rule Virus_Hijack_Trojan_GenericKDZ_98113_226 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_226.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "290942ebe3a88a32fa9491b5e3cd4a1a6eab18776a1989364c264921540f9675"

  strings:
    $s1 = "F4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}