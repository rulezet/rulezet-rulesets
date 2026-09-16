rule sig_20160525_0717ebfcbb76513a65ac6677bdfd1c00 {
  meta:
    description = "datamaliciousorder - file 20160525_0717ebfcbb76513a65ac6677bdfd1c00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c6497d557ade7ee6ea6b002b1721148b6830256b2c36edb24289d7ed2049419"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}