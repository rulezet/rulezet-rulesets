rule Virus_Hijack_Trojan_GenericKDZ_98113_59 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_59.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbe397c74904b22372537d4b9d1302244a77d5b9c8347f527ded25095f09d676"

  strings:
    $s1 = "lby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}