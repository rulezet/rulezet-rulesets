rule Trojan_Autorun_Win32_Virlock_Gen_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fd6e0592a5165d6cdca86eea70087fc0e366f5f4fefdd673f61ceb724ff196a"

  strings:
    $s1 = "Rich!l" fullword ascii
    $s2 = "SIRE,b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}