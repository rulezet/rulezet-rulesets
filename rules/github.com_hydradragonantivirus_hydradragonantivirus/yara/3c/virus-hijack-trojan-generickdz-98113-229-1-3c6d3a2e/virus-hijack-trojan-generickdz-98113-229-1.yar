rule Virus_Hijack_Trojan_GenericKDZ_98113_229_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a677c8b00c3aa90f9768677db645d8dd2310555220c5b88b67bd2a7e2d439b78"

  strings:
    $s1 = "Y<MoKO" fullword ascii
    $s2 = "q<SHEth" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}