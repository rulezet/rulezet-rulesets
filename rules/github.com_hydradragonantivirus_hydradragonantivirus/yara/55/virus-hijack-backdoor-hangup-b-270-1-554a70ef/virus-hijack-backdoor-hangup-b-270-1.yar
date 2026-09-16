rule Virus_Hijack_Backdoor_Hangup_B_270_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_270_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b34837e2741948350172a3f30ba79e375216edda557f0dc546036d3db5380e2"

  strings:
    $s1 = "Hello %s %s 127" fullword wide
    $s2 = "Value system32" fullword wide
    $s3 = "vags Version 1.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}