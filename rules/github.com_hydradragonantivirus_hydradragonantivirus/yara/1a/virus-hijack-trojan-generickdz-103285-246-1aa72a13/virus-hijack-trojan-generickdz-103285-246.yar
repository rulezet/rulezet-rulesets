rule Virus_Hijack_Trojan_GenericKDZ_103285_246 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_246.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dfed68d8440de702b6d371645a617f7b6de9371eb1a77266beed2d48d8853e0"

  strings:
    $s1 = "2P(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "2P(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}