rule Trojan_Autorun_Win32_Neshta_A {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13ff0ee6cf10885b8e130df071bf4042fceef22dcc655b5779149e2dc4572654"

  strings:
    $s1 = "<description>Green software</description>" fullword ascii
    $s2 = "code@Adv" fullword ascii
    $s3 = "Notepad2 Text Editor" fullword wide
    $s4 = ", file#R" fullword ascii
    $s5 = "@NibS;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}