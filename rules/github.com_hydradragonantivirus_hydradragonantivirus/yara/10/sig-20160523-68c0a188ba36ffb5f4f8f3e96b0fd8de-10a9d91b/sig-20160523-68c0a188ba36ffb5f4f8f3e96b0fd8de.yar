rule sig_20160523_68c0a188ba36ffb5f4f8f3e96b0fd8de {
  meta:
    description = "datamaliciousorder - file 20160523_68c0a188ba36ffb5f4f8f3e96b0fd8de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5373c5ae444cc0cc377aa36edc5a20cb36ff69c87b77b8cc1f9effa9459598dd"

  strings:
    $s1 = "split('').reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}