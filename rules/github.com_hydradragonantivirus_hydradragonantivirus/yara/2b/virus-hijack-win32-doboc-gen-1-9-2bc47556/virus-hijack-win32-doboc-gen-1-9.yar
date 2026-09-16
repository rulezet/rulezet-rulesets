rule Virus_Hijack_Win32_Doboc_Gen_1_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab5e53e18aba69074ae118776f960a7724619be7ac6359827f0487ec09ca066"

  strings:
    $s1 = "DIG & FISH, PTY0" fullword ascii
    $s2 = "LEVEL 1 60 WILSON STREET1" fullword ascii
    $s3 = "DIG & FISH, PTY1" fullword ascii
    $s4 = "SOUTH YARRA1!0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}