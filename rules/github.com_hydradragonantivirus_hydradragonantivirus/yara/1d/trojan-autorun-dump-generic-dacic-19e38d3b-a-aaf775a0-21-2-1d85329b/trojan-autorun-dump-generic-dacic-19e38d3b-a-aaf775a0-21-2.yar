rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_21_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14ec7e464f021e9198d4bc2be511e3e054f9e6e8d02b5852a6da56a88d0fe13e"

  strings:
    $s1 = "set exeFile=%TEMP%\\System.exe" fullword wide
    $s2 = "set logFile=%TEMP%\\proclog.txt" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}