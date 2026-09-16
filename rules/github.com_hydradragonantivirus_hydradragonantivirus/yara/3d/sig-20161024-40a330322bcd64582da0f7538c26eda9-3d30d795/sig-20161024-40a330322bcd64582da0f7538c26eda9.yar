rule sig_20161024_40a330322bcd64582da0f7538c26eda9 {
  meta:
    description = "datamaliciousorder - file 20161024_40a330322bcd64582da0f7538c26eda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab7e3585323441766d2692f1108b3bb6cc02a0c01e1799079b7d117e15e66bee"

  strings:
    $s1 = "} while (yy++ < io);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}