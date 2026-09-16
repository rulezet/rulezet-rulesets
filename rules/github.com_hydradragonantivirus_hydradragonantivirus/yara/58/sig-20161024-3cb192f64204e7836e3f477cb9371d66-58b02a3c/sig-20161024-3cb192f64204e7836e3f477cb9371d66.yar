rule sig_20161024_3cb192f64204e7836e3f477cb9371d66 {
  meta:
    description = "datamaliciousorder - file 20161024_3cb192f64204e7836e3f477cb9371d66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9419d1161bfe55ac704ccce3f2b2424a5120365daa98faed7ed669ad7e169bcb"

  strings:
    $s1 = "} while (pv++ < xp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}