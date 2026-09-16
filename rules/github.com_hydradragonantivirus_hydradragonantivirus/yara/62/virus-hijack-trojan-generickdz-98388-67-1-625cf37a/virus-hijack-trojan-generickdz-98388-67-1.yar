rule Virus_Hijack_Trojan_GenericKDZ_98388_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96d64d021d31678a600a074ae37df352f886c6aad375fa9f7234d14aaeba9a76"

  strings:
    $s1 = "vIrL[OF" fullword ascii
    $s2 = "WacK<4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}