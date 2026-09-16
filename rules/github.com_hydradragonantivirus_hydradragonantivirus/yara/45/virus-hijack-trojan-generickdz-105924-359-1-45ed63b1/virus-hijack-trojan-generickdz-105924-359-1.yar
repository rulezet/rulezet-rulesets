rule Virus_Hijack_Trojan_GenericKDZ_105924_359_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_359_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f846b9298438e6950c953044026327169c5f4379046024529c8c1ad61d34d48"

  strings:
    $s1 = "|:Yite$L" fullword ascii
    $s2 = "g]auTE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}