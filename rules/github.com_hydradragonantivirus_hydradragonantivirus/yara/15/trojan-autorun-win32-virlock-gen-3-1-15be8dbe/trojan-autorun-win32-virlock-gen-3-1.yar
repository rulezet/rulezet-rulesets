rule Trojan_Autorun_Win32_Virlock_Gen_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c8226212a70b0dcc074488031b9605508e8c5e6215c2bf953b4692a7367aac6"

  strings:
    $s1 = "+;DRAm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}