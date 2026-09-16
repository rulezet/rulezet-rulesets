rule Virus_Hijack_Trojan_GenericKDZ_98388_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d21399ffe0f30a10ad8bca5e18c52a8077db5e9a60dcd583fd77a458e0527d9"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}