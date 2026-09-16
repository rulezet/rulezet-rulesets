rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5bcc2250b755befeee61cc533e95444bf863b94c78e85341f8413df795a71af"

  strings:
    $s1 = "CORE;5" fullword ascii
    $s2 = "g%lOSS" fullword ascii
    $s3 = "i]gill" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}