rule Virus_Autorun_Win32_Neshta_A_50 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e54582fe57456a06f20dee2c0012772760b8e1574d064891de7b8739854898d"

  strings:
    $s1 = "__MediaHost__:client lost. will close." fullword ascii
    $s2 = "local:HitPawMediaInfo" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}