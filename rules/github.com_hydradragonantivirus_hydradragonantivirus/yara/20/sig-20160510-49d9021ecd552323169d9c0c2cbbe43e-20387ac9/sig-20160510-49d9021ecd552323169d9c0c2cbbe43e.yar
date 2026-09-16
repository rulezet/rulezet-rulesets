rule sig_20160510_49d9021ecd552323169d9c0c2cbbe43e {
  meta:
    description = "datamaliciousorder - file 20160510_49d9021ecd552323169d9c0c2cbbe43e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff10f0e4693c78fee551ce5a07d396ad7534709a1b624d0831975fb94e6e517"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b m(q,V){b 9o(4Q){c 5.T(4Q)}if(\"9p\".O(\"9n\")!=-" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}