rule Trojan_Danger_Trojan_GenericKD_72853156_113_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_113_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9de8900270e6b44e11ca7c5dd4391f404cf84cba22c2c6906f2f2c34bc1828f8"

  strings:
    $s1 = "Progra Document" fullword wide
    $s2 = "flash " fullword wide
    $s3 = "SIzY)4" fullword ascii
    $s4 = "0Park Arena, Komaki, Aichi, Japan, 12. vacant WBO" fullword wide
    $s5 = "A kip is a non-SI unit of force. It equals 1000 pounds-force, used primarily by American architects and engineers to measure eng" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}