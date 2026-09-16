rule sig_20160525_0580a62d3007d6f099ad2602fd996cf1 {
  meta:
    description = "datamaliciousorder - file 20160525_0580a62d3007d6f099ad2602fd996cf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e63117899aee3009937a04503e19778721539a9cab387e14de74c9457169fd93"

  strings:
    $s1 = "loca rav" fullword ascii
    $s2 = "dart rav\\n;\"16x\\\\S\" = ecapsetihwxelft rav\\n;\"e67x\\\\\" = modnart rav\\n;\"Ff6x\\\\T\" = deerdt rav\\n;\"56x\\\\li\" = sd" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}