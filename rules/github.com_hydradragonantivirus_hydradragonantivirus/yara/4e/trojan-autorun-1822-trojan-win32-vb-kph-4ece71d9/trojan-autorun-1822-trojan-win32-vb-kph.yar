rule Trojan_Autorun_1822_Trojan_Win32_VB_kph {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_1822.Trojan.Win32.VB.kph.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d503f8a6cd7ee555a95095b37ec63c8691552dfbce054a22deefdac903b202b"

  strings:
    $x1 = "cmd /c copy msgsm.exe %systemroot%\\system32" fullword wide
    $x2 = "cmd /c copy mgsgm.exe %systemroot%\\system32" fullword wide
    $x3 = "cmd /c copy MSWINSCK.OCX %systemroot%\\system32" fullword wide
    $s4 = "@*\\AF:\\LANGUAGEZ\\vs\\Visual Basic 6 Portable\\AutoPlay\\Docs\\Portable.VB6\\Project1.vbp" fullword wide
    $s5 = "F:\\LANGUAGEZ\\vs\\Visual Basic 6 Portable\\AutoPlay\\Docs\\Portable.VB6\\VB6.OLB" fullword ascii
    $s6 = "Cracker" fullword ascii
    $s7 = "Cracker 7.1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}