rule sig_20170313_7648be03dabcb405d754bc9700d28dbd {
  meta:
    description = "datamaliciousorder - file 20170313_7648be03dabcb405d754bc9700d28dbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "062dab7291ba64380c3cc0cbec0385be864d1e6b50843903dcad92a7fee40ac2"

  strings:
    $s1 = "var x = new Array(\"realtyrenders.com\", \"avivamientohoy.com\", \"powerofattorney-online-form.com\", \"redhawkrecords.com\", \"" ascii
    $s2 = "var x = new Array(\"realtyrenders.com\", \"avivamientohoy.com\", \"powerofattorney-online-form.com\", \"redhawkrecords.com\", \"" ascii
    $s3 = "lAJQFZtJnuwRd8-OWxJXXQ0\"; try { x[i] = z9+x[i]+z10; e.open(z8 + z6, x[i]+m, false); e.send(); var z3 = e.responseText; if (z3.l" ascii
    $s4 = "ngth > 1000) { if (z3.indexOf(m) > -1) { var z3 = z3.split(m); var z3 = z3.join(z4); eval(z3); break; }; }; } catch(e) { }; };" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}