rule VirusShareTrojanVbCrypt250_2 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanVbCrypt250_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41fa54f264b6a1f8742804bdac4c708fa87a0021efdc0800858fbb2b0e2e7187"

  strings:
    $s1 = "<description>Windows Error Reporting</description>" fullword ascii
    $s2 = "AHKCU\\Software\\Microsoft\\Internet Explorer\\Settings\\Anchor Color" fullword ascii
    $s3 = "$@Unknown exception" fullword ascii
    $s4 = " 'X7 Rich&X7 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}