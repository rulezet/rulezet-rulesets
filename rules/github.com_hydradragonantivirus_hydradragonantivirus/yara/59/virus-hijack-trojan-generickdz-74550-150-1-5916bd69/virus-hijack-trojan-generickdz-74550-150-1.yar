rule Virus_Hijack_Trojan_GenericKDZ_74550_150_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_150_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26e00be6b7a5d515b9f7b92c7ea7fbddd5b16a4df754fdddc477d39a574a2e2c"

  strings:
    $s1 = "P{#rasp@F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}