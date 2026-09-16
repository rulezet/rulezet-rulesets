rule Trojan_Danger_Trojan_GenericKD_72304918_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d25f9000cbf2f26f458940d80284d046df82c4835381b3aa06747cb2a574c0c4"

  strings:
    $s1 = "JWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}