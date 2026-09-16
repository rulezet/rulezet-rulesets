rule sig_20160510_73653d88f273c26bb635992a9756438b {
  meta:
    description = "datamaliciousorder - file 20160510_73653d88f273c26bb635992a9756438b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2ff294bc55675cdfd23dcb39200fb87be5ac3cc9d5c2c8b935f0367be11d72"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d p(r,18){if(\"\\\\w\\\\h\\\\n\\\\J\\\\v\\\\D\\\\J" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}