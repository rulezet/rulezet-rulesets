rule Virus_Infector_Win32_Expiro_Gen_7_166 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_166.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81c7f7db88411cac36fe510427b6e8fb0f03f36109fc6195011a1d059cb67b88"

  strings:
    $s1 = "YKT.[mEwl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}