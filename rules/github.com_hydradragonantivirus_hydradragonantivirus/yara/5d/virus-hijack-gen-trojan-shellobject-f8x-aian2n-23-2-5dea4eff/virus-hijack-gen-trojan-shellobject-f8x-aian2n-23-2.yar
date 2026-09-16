rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_23_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6563f7f1256c01df7e27c94d6e53e951f9a533a19274b5984c4c994d58f42536"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;" fullword wide
    $s2 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}