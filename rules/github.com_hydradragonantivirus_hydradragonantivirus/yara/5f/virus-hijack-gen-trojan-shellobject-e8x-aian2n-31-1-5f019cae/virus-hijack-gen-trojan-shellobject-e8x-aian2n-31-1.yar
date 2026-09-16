rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3242ebe7c4a3ddd6261de14ff085de1feb515866e0ca2952f9a2411eeb070b6"

  strings:
    $s1 = "Select * from AntiVirusProduct" fullword wide
    $s2 = "alive??" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}