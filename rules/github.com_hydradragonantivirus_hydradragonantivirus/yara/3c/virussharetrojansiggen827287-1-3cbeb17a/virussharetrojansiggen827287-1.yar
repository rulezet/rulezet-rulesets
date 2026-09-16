rule VirusShareTrojanSiggen827287_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca28d755a65fadb1820fcb54fff1011646c183eae971e9a7740a9afee3df570f"

  strings:
    $s1 = "Malware Test File" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}