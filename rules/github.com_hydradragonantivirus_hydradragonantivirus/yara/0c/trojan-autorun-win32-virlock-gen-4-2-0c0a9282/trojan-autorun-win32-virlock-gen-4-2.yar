rule Trojan_Autorun_Win32_Virlock_Gen_4_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49af3ba9e4a3f3f61b50842ebbc20aa73328542c189984aadc868295c19138a7"

  strings:
    $s1 = "rorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}