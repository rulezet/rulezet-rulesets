rule Virus_Hijack_GenPack_Backdoor_Hangup_B_301 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_301.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48e07192f6a2f78303336658bf5252ed8ccd02beeb8bc493c268dd28c1418be3"

  strings:
    $s1 = "+wof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}