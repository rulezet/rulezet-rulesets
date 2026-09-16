rule Virus_Sysbot_Generic_Dacic_Emdup_A_2B7569A8 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Dacic.Emdup.A.2B7569A8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd90cdb231e06c8d7c422c30b5c9258df8a39b98a80ced651f1f9cf4f53a65ea"

  strings:
    $s1 = "Copyright 2022 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}