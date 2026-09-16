rule Trojan_Danger_Trojan_GenericKD_72853156_202_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5347aea56581b89c9fb660cba31e5a405951cde3b73c6d4be3c74ab2c20c555f"

  strings:
    $s1 = "@!SlAW" fullword ascii
    $s2 = "wEde#%" fullword ascii
    $s3 = "Z?@agOn" fullword ascii
    $s4 = "\"GApO%" fullword ascii
    $s5 = "P<vOta" fullword ascii
    $s6 = "hAko%#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}