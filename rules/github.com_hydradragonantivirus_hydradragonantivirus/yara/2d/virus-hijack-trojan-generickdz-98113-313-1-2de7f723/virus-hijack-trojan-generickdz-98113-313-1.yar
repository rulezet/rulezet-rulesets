rule Virus_Hijack_Trojan_GenericKDZ_98113_313_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_313_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88987f1ec8628bda39465baa3cf04bd4f72734cd779bb37dd24bb8abeb353a69"

  strings:
    $s1 = "item<Xj" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}