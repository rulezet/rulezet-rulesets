rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b6a60d1c33c56cad75ffd849b20805cdddade1581a556dd2d9e13ffe25672c9"

  strings:
    $s1 = "gUSLa]{" fullword ascii
    $s2 = ">A`hONK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}