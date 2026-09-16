rule sig_20160421_6215946aac3db54a5a45dbfaa039f486 {
  meta:
    description = "datamaliciousorder - file 20160421_6215946aac3db54a5a45dbfaa039f486.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0c6001c8ab1ca748a1a420b9f0d116de0b4f4cfbfc49e3ecbdc2a96c7f26a37"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 3K(3J,5R){g(c){9 c:e(3J===f){8 1r=5Q;1r=45-5S;8 " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}