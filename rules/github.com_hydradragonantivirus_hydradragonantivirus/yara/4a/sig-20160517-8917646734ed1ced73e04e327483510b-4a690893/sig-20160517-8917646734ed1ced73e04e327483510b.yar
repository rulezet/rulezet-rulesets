rule sig_20160517_8917646734ed1ced73e04e327483510b {
  meta:
    description = "datamaliciousorder - file 20160517_8917646734ed1ced73e04e327483510b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98811a133881241c9ba116d10e35038158caa73ad60ad5cf8d7cb21eb133c11e"

  strings:
    $s1 = "var d2gsqm='vlspsuasvjxnrejul4 qpafbwfb14xvdc4vkvbmctebtdalacscnnrnorhv2adkdnobhtuepbmiblchpmjp2=zheby\\'twqhrtuybzmcz4goinaxuai" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}