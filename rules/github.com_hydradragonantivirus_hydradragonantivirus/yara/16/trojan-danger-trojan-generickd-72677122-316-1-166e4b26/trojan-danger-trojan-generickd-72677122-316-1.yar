rule Trojan_Danger_Trojan_GenericKD_72677122_316_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca973ec29fbb11ddc5a849bee2f8b2a1a61db30f697a8a684265c7d484b5242"

  strings:
    $s1 = "k[NOON" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}