rule sig_20160525_5f9d560cb92b767ef498b4a7656d653e {
  meta:
    description = "datamaliciousorder - file 20160525_5f9d560cb92b767ef498b4a7656d653e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da9b1248cb40e6eac7dbd362e2066dae7c52ca62701aaae270082b5923c2b317"

  strings:
    $s1 = "nete rav\\n;\"13x\\\\r\" = ssorcae rav\\n;\"03x\\\\d\" = tsilslianbmuhtoe rav\\n;\"o66x\\\\\" = cthe rav\\n;\"xd6x\\\\\" = rered" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}