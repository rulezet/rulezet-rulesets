rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adee1e696d838d24f20ffa6d9ea0f57edc1b1232f16344cb80f3375166cf5fdd"

  strings:
    $s1 = "Q<VlEI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}