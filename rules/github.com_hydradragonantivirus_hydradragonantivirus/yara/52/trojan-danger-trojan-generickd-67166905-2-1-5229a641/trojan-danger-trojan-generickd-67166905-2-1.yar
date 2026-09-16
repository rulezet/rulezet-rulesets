rule Trojan_Danger_Trojan_GenericKD_67166905_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08aacea2e2e6fc9555af9054bd2c2a57ea9c280869d674f749ec2ac6fb933ec1"

  strings:
    $s1 = "]must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}