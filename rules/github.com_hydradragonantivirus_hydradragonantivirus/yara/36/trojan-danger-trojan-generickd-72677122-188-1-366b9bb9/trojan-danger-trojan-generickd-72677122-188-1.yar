rule Trojan_Danger_Trojan_GenericKD_72677122_188_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7fdf9804c494ea824f7e98710ca13075922ceaf45a7fd0851d4ab44541ee8c0"

  strings:
    $s1 = "Encode:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}