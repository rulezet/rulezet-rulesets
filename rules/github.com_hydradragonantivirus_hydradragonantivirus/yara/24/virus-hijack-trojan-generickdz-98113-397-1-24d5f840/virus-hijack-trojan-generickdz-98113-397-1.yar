rule Virus_Hijack_Trojan_GenericKDZ_98113_397_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_397_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4462602eb9fa5b2c6344bf1a1e8fd225fc74e378fa557f9d9dee8170f99e1436"

  strings:
    $s1 = "= WhIr:D3" fullword ascii
    $s2 = "raIL: IV" fullword ascii
    $s3 = "' YERk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}