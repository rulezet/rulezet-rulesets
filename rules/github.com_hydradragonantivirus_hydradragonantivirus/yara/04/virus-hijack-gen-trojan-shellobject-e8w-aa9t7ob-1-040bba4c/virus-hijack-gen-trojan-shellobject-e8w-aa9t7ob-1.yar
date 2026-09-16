rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b9eb61d7a832cf807fe8897ba6f4b9cc91f8370614f929725bc3dca3756ecc8"

  strings:
    $s1 = "_}hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}