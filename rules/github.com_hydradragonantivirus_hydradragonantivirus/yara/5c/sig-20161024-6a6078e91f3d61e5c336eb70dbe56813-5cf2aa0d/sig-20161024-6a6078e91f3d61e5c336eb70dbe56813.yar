rule sig_20161024_6a6078e91f3d61e5c336eb70dbe56813 {
  meta:
    description = "datamaliciousorder - file 20161024_6a6078e91f3d61e5c336eb70dbe56813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c41ceb6ea9405167cc08066a8498e8c427f3ee60d9fa6e8285c939da990e60e"

  strings:
    $s1 = "} while (au++ < ul);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}