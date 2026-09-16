rule Virus_Infector_Win32_Expiro_Gen_7_209 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_209.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fbff2d35d0225582efe5f18a2582198cf78c4de1fc8e95564a36f2a121dbdee"

  strings:
    $s1 = "q|T5i&oPAl" fullword ascii
    $s2 = ":TOle." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}