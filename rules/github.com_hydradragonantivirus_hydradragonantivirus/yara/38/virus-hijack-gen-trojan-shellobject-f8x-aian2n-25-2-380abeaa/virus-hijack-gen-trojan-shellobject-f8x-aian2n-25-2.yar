rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_25_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47212dcd73cd7eed6b319e1281586c3ff7d22939e2ec65f6afa75fb18f5f0ff2"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;" fullword wide
    $s2 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}