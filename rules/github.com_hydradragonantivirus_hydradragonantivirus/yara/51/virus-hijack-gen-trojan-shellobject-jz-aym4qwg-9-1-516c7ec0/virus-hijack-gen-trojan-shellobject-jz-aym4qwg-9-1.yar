rule Virus_Hijack_Gen_Trojan_ShellObject__JZ_ayM4QWg_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "870498c3f8b8ac91dede60398727855a0934b3a9e3950e75bae4278f32df7612"

  strings:
    $s1 = "%LALo@,4" fullword ascii
    $s2 = "OcHt&k" fullword ascii
    $s3 = "VeIl%T" fullword ascii
    $s4 = "birL;f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}