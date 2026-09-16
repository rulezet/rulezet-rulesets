rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddc2218dcf2c4175f58dcf4a79be9234cd8bf2fd67a4625683804019d2a51d2"

  strings:
    $s1 = "n#welK" fullword ascii
    $s2 = "':deRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}