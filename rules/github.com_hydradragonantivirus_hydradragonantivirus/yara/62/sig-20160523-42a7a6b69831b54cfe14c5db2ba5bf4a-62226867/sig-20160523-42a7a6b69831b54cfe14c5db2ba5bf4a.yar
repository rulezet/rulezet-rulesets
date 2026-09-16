rule sig_20160523_42a7a6b69831b54cfe14c5db2ba5bf4a {
  meta:
    description = "datamaliciousorder - file 20160523_42a7a6b69831b54cfe14c5db2ba5bf4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c30d6a455addb322e83087afa33922fa0771a0e535cef1a719f8995000bfe00"

  strings:
    $s1 = "reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}