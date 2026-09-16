rule sig_20160510_45307c74e77821c53d8003ee78c773a5 {
  meta:
    description = "datamaliciousorder - file 20160510_45307c74e77821c53d8003ee78c773a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe23b36cada0df1d119d1abe1ddd7ef56a4bbecdabff5217fc3fd07a915c2b14"

  strings:
    $s1 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 3H(1b,a,s,f){4 nc=1;if(5.P(nc)>0){4 J=9}6{4 9O=9" ascii
    $s2 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}