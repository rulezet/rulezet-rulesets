rule Virus_Hijack_Trojan_GenericKDZ_98113_348_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_348_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "934c27aad25249fe3b01e2cf48e5f331960494b9ecd66e73c8d3570eec082aa1"

  strings:
    $s1 = "%sTIFE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}