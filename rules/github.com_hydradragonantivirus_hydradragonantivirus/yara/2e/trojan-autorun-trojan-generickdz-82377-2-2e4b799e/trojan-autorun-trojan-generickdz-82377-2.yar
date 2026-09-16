rule Trojan_Autorun_Trojan_GenericKDZ_82377_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.82377_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e8c41da84c5809b249df760de1589215834f9c7ba1b25848f24d336dbd18cc"

  strings:
    $s1 = "af6hj<liin>prDtqqvFxzL|yy~N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}