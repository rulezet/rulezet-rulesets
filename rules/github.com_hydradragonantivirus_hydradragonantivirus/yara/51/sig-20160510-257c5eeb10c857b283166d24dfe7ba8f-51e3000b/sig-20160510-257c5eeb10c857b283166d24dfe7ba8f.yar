rule sig_20160510_257c5eeb10c857b283166d24dfe7ba8f {
  meta:
    description = "datamaliciousorder - file 20160510_257c5eeb10c857b283166d24dfe7ba8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfab1bdff358d700c89cd8900653aa226bf0ac4f88c0079cae951481ffe93fdb"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 1w(4t){4 4m=-1;if(6.I(4m)>=0){4 gT=\\'\\'}5{4 gH" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}