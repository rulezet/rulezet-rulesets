rule sig_20160425_efc6dec4c77c6f4e18bfd15935f5ce0a {
  meta:
    description = "datamaliciousorder - file 20160425_efc6dec4c77c6f4e18bfd15935f5ce0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c3c40577d941cca1bb15f58f52e5a251f48d9c90e65adb7395bc9e514204a11"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 407(545,548){8" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 407(545,548){8" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}