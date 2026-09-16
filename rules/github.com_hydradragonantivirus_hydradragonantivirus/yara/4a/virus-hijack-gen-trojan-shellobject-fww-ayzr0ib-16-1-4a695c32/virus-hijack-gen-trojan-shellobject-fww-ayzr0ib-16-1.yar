rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7102d65483413cd0f655c35cb370af17b2c7034df099b31dc66905e2c2525aac"

  strings:
    $s1 = "Invalid parameter detected in function %ls. File: %ls Line: %d" fullword wide
    $s2 = "Expression: %ls" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}