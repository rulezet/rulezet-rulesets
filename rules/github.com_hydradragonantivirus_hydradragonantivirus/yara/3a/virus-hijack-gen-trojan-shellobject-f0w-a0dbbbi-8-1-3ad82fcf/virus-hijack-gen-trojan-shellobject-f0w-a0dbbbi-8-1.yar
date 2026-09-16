rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f31d14a227768a0d7e4fa1c74fa22668824af523978feae434f18d0179cad680"

  strings:
    $s1 = "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal\" \"Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f" fullword ascii
    $s2 = "Information System Team1" fullword ascii
    $s3 = "Microsoft Windows Millenium Edition " fullword ascii
    $s4 = "TAhnLab V3 Internet Security 2009 Platinum" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}