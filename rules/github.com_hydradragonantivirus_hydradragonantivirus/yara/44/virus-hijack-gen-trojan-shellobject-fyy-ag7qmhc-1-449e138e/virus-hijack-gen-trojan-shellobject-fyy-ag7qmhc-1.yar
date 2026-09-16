rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1efcd572779ffd6e3f58e61677ec7c3adb01073b674fa391b5c3931ce65d9ec1"

  strings:
    $s1 = "%1e&arEd]Me" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}