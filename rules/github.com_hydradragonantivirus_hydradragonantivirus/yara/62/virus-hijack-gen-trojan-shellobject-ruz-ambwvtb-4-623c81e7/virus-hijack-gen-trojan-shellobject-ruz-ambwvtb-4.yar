rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86943f498a8ac0d6c0bc2e530dd4ae75066a260d33a941a644b96585197f52d5"

  strings:
    $s1 = "quiZ&\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}