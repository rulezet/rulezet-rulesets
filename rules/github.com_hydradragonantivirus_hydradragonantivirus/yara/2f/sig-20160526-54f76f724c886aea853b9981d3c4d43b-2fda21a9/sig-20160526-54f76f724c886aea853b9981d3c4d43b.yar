rule sig_20160526_54f76f724c886aea853b9981d3c4d43b {
  meta:
    description = "datamaliciousorder - file 20160526_54f76f724c886aea853b9981d3c4d43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5f3ce79237c8a27aada60ec354edc10dcc683bc4ef5788903d6329c207f4bb"

  strings:
    $s1 = "\"Ff6x\\\\\" = d7lRKICLO rav\\n;\"c6x\\\\i\" = z2cVJATDE rav\\n;\"56x\\\\\" = e8gFNVXRP rav\\n;\"56x\\\\solc\" = p2pGREVCV rav'[" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}