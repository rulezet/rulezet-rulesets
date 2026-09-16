rule sig_20160525_c07dc3de7239c4626ebc27aa3276b742 {
  meta:
    description = "datamaliciousorder - file 20160525_c07dc3de7239c4626ebc27aa3276b742.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b45603af35063c697ec10babde9b58cc987e97c820f34ef2eab98f1a6f1e433e"

  strings:
    $s1 = "loca rav" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}