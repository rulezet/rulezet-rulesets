rule sig_20160510_c70c8a3e48606c87ef2445a0517bec64 {
  meta:
    description = "datamaliciousorder - file 20160510_c70c8a3e48606c87ef2445a0517bec64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668adffd09dbd16999138a2d2d1701e60f7be77f3d3fefaec656cc66c4d38034"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('u 2O(){if(\"7b\".Q(\"77\")==-1){70=7}6{d=\\'\\'}4 " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}