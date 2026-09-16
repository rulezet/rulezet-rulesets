rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_1_Virus_Hijack_69 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash2       = "d6767a4b06185a363a0348866269fb91d958be7963fa9f901ec3f2503d418fef"

  strings:
    $s1 = "ERROR: GetLogFile(WINDOWS_CBS_LOG_FILE) failed (%X)" fullword wide
    $s2 = "WARNING: GetNISSupportDir() failed (%X)" fullword wide
    $s3 = "Getting CBS log..." fullword wide
    $s4 = "last known good" fullword ascii
    $s5 = "You cannot specify both -All and -DynamicSignatures" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}