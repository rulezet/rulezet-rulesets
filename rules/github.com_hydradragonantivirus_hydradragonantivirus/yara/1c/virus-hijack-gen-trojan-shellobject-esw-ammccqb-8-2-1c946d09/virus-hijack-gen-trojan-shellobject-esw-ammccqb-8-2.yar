rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef91081c17b20e5cbd0d1c4dd5a0b85d8046e4692d67dde96975ebde8be39de5"

  strings:
    $s1 = "COWLING" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}