rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_aKTibuk_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fe2ecb74b67b78850fa3bf3b3e3a0e90cdd3118bfdd4ee1612cec0e84feba6b"

  strings:
    $s1 = "new Adapt EnableLoader" fullword ascii
    $s2 = "OID_DEVICE_TX_BASE = -%d.%d.%d disk %s nvu" fullword ascii
    $s3 = "GetBase Train %d" fullword ascii
    $s4 = "Monit fill DSTATE_COMCTL_FOUND" fullword ascii
    $s5 = "FinalPowerDown by Reneg Noise" fullword ascii
    $s6 = "MOH  MH- cannel: %f" fullword ascii
    $s7 = "Microsoft Visual Mode" fullword ascii
    $s8 = "Clease constate 2" fullword ascii
    $s9 = "Microsoft Visual held" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}