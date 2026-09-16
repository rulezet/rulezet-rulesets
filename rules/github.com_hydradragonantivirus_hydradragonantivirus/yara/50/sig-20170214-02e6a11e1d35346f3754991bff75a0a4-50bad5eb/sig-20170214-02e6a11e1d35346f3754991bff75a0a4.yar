rule sig_20170214_02e6a11e1d35346f3754991bff75a0a4 {
  meta:
    description = "datamaliciousorder - file 20170214_02e6a11e1d35346f3754991bff75a0a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f17bfc6f1d51946dcd7fc15a5ad687282ebbf7d1d79e15862e5812f760411c"

  strings:
    $s1 = "var z9 = \"http://\"; var x = new Array(\"azlivesound.com\", \"realizedworth.com\", \"evergladesit.com\", \"mapoftexas.net\", \"" ascii
    $s2 = "var z9 = \"http://\"; var x = new Array(\"azlivesound.com\", \"realizedworth.com\", \"evergladesit.com\", \"mapoftexas.net\", \"" ascii
    $s3 = "RtPG20Wd0wPXSBS7UF2DQ0\"; e.open(z7, x[i]+m, false); e.send(); var z3 = e.responseText; if (z3.length > 1000 && z3.indexOf(m) > " ascii
    $s4 = "1) { var z3 = z3.split(m).join(z4); eval(z3); break; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}