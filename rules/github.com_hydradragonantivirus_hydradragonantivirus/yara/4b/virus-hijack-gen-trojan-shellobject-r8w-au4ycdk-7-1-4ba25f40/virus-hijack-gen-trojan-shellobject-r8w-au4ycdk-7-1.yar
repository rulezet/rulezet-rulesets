rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aafb6a76fab108564fabbb9ef5eb0c13b1bbfd955ecba08d7df1d9289162a499"

  strings:
    $s1 = "ShIp<d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}