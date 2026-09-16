rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c10dceaf5e283e8e830170d1d587bd8392f34cfe6db75f5b19b1f2a352806e6"

  strings:
    $s1 = "l!CUbe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}