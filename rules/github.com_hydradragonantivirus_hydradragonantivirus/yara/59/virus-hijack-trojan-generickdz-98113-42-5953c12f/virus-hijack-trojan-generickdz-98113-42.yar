rule Virus_Hijack_Trojan_GenericKDZ_98113_42 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_42.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cde8e323bde386a6340f6ed2de818b07b849faca4b0b167ffe4a4a9d1271cb46"

  strings:
    $s1 = "\"%your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}