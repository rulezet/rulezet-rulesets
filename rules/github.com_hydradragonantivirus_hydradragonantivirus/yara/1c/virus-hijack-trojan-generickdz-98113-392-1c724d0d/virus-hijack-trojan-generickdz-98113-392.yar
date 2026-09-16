rule Virus_Hijack_Trojan_GenericKDZ_98113_392 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_392.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8ce31f4e2e94400a2d423cb9ecb8d1d4210bc1b844bfab1a86204d6c709080"

  strings:
    $s1 = "0=4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}