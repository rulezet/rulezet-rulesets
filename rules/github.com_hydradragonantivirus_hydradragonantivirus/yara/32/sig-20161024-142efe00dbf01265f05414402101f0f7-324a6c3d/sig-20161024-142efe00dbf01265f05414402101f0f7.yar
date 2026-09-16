rule sig_20161024_142efe00dbf01265f05414402101f0f7 {
  meta:
    description = "datamaliciousorder - file 20161024_142efe00dbf01265f05414402101f0f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96720fcb47d9c0043de3347ebbafca6d1973d207a33f713bb18228d79c8eea91"

  strings:
    $s1 = "} while (eq++ < gq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}