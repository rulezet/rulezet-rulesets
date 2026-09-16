rule sig_20160523_3dac079dd215c2d72765061647b939a2 {
  meta:
    description = "datamaliciousorder - file 20160523_3dac079dd215c2d72765061647b939a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c58d9cc39ceb134044144d5b4d677baf11e51e0ebbb6989660f4150f41207752"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}