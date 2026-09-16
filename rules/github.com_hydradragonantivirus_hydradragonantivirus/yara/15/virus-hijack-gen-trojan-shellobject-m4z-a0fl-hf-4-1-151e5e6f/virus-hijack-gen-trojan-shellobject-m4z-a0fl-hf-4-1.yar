rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e42809de320718f7f9baeee70a47adcae7cd2c8216154b95491c4f810c65bd3"

  strings:
    $s1 = "mima[TC(" fullword ascii
    $s2 = "N@BInD" fullword ascii
    $s3 = "Z#EMMa" fullword ascii
    $s4 = "D%PiSO" fullword ascii
    $s5 = ":?troD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}