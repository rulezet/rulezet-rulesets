rule Trojan_Sysbot_Trojan_GenericKD_73090062_36_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.73090062_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86d936e32f50f55b663117ec9d5060fb9c4f59a17ec1da04f555ee18f9a244e4"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}