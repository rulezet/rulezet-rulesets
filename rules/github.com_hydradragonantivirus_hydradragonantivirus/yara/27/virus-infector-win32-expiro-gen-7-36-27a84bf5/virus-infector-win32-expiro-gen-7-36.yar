rule Virus_Infector_Win32_Expiro_Gen_7_36 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f299c7499c195243b0a3657b76992df8d5c42f23a51f10bbd597f64d4c402af3"

  strings:
    $s1 = "UTas(QK," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}