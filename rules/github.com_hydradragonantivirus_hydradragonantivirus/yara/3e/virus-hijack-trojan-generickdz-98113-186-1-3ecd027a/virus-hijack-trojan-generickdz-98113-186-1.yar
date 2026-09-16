rule Virus_Hijack_Trojan_GenericKDZ_98113_186_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "290f6fbe7d947cf02766e0194cb28759522979278074142f96b9bbb77cacf411"

  strings:
    $s1 = "~<GRow" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}