rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30fd5473660be7040341a4f2b979af0e1e029c32b1e350eed3950a0d07f0e3c3"

  strings:
    $s1 = "#shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}