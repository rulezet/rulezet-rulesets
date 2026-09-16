rule sig_20160426_2dac314aca767b2cc139fcc0348b56d4 {
  meta:
    description = "datamaliciousorder - file 20160426_2dac314aca767b2cc139fcc0348b56d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "273af1dfe17063d0efc72c9c9c3d3b091c75128ab381250ac060f31c39ad0dbb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 188(485,265,20" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('16 188(485,265,20" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}