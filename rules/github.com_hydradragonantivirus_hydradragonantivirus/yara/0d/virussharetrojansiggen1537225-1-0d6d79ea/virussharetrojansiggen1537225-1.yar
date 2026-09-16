rule VirusShareTrojanSiggen1537225_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1537225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "521798e7fc5b493255379ac100b4a7cc094c46d0ab0e572097bd6f5045cff824"

  strings:
    $s1 = "EiOEEVHmyWZmVhMLlfMGAuAaJCyGN8xt@<c>72`M#Z(\"'JS@exoN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}