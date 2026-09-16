rule Trojan_Autorun_Trojan_GenericKD_72517131_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e96c2a6a76f8dcda541f32b52e1f1c3293a2c339f6b8e6377ae567a80d408c9"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup co" fullword ascii
    $s2 = "e option to convert your trial rights to subscription or" fullword ascii
    $s3 = "a third party without restriction on the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}