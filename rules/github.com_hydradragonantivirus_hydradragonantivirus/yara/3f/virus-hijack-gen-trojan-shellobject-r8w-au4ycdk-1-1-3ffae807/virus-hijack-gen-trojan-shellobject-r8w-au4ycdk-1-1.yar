rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "509d4f3d65ff658ddad1217d0eae77a498589e35546bc403455f64eaa59363f5"

  strings:
    $s1 = "mooth#x:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}