rule Virus_Infector_Dropped_Win32_Elkern_B {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Dropped.Win32.Elkern.B.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94aee4a5852d187a1541a241f61472e1f19d023f68fe42bc973e28d691f7534b"

  strings:
    $s1 = "Java(TM) Platform SE 8 U221" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}