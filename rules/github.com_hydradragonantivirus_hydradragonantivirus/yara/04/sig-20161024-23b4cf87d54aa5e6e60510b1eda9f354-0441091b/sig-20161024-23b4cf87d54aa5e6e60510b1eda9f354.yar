rule sig_20161024_23b4cf87d54aa5e6e60510b1eda9f354 {
  meta:
    description = "datamaliciousorder - file 20161024_23b4cf87d54aa5e6e60510b1eda9f354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b3ed42337c4be6e30d8b035b8b26cd2a324033829430713356b5aef5a26789"

  strings:
    $s1 = "} while (br++ < ih);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}