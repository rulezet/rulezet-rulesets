rule Virus_Infector_Win32_Expiro_Gen_7_138 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_138.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adf56c306fd48919fe2e55d3873218b644bf95c7772f62cec9d7f968362acdf2"

  strings:
    $s1 = "UTas(QK," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}