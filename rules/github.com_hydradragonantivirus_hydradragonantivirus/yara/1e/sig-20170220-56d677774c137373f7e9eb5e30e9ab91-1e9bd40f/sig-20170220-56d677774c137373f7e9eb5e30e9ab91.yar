rule sig_20170220_56d677774c137373f7e9eb5e30e9ab91 {
  meta:
    description = "datamaliciousorder - file 20170220_56d677774c137373f7e9eb5e30e9ab91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a573f9d7e035eaf9a8a418c141c31e23c63adcda185b6f5a2dda557146147416"

  strings:
    $s1 = "var x = new Array(\"riavesti.com\", \"author31.com\", \"mexicodiamondresorts.com\", \"phoenixweddingbands.com\", \"libertadcarib" ascii
    $s2 = "var x = new Array(\"riavesti.com\", \"author31.com\", \"mexicodiamondresorts.com\", \"phoenixweddingbands.com\", \"libertadcarib" ascii
    $s3 = "pyZuyoiJYQMEJ2NyvPBktYS-22Yndgh9BmpwDQ0\"; try { x[i] = z9+x[i]+z10; e.open(z8 + z6, x[i]+m, false); e.send(); var z3 = e.respon" ascii
    $s4 = "eText; if (z3.length > 1000) { if (z3.indexOf(m) > -1) { var z3 = z3.split(m); var z3 = z3.join(z4); eval(z3); break; }; }; } ca" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}