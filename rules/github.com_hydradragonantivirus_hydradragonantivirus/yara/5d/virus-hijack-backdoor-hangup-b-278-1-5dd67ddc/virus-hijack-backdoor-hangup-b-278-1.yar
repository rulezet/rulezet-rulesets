rule Virus_Hijack_Backdoor_Hangup_B_278_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_278_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5e4a5a56f3392143e64c8c7cb1c914cf35f379a18a4db29697c013fced2076"

  strings:
    $s1 = "reg delete \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Active Setup\\Installed Components\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}