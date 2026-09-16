rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25fae0ca77d3574c660443b962834a3603c74fc426dcb1ea2a0d9f77719e4398"

  strings:
    $s1 = "KERN`L32.dql" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}