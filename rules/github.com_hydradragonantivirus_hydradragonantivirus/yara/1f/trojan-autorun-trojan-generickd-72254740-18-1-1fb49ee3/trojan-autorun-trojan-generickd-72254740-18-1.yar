rule Trojan_Autorun_Trojan_GenericKD_72254740_18_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72254740_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3006e9dc7e9eacd02ba8aafeae32e7453c1b5569e0ad061793a2b431c33c6f6d"

  strings:
    $s1 = "i4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}