rule Virus_Autorun_Win32_Neshta_A_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7061446257714da1fdd69154f97ee6038feb6d76ee697fa634ee08cb8f76c66"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}