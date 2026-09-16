rule Virus_Hijack_Dump_Generic_KillMBR_A_A468FC31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dump.Generic.KillMBR.A.A468FC31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d08bbb1e8d75b2ad46bec4836df67607717f622a56307b7563f2eccd8085ef"

  strings:
    $s1 = "Semielision" fullword wide
    $s2 = "Serpentinic" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}