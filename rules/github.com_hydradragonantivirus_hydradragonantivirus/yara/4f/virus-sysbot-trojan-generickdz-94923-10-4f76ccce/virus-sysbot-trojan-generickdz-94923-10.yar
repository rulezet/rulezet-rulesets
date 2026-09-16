rule Virus_Sysbot_Trojan_GenericKDZ_94923_10 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cdd04d426e1a55ec07ca14d543e79b98e723a130e5f80efcdbc43d300bade09"

  strings:
    $s1 = "The software also is not licensed for commercial hosting. For more information on multiple user scenariosa952fc166c78a9c32206993" ascii
    $s2 = "The software also is not licensed for commercial hosting. For more information on multiple user scenariosa952fc166c78a9c32206993" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}