rule Virus_Hijack_Trojan_GenericKDZ_98113_284 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_284.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a10737af5ff7551ddf0a46df15a9cea68d1a16a4d2c956434ab18076fdeac03"

  strings:
    $s1 = "q4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}