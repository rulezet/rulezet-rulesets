rule Virus_Hijack_Trojan_GenericKDZ_98113_280 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_280.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c76857d5ea7469ac338667f0e4e3c757d3f571cb05e19735f05705c7bfb5720e"

  strings:
    $s1 = "KB4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}