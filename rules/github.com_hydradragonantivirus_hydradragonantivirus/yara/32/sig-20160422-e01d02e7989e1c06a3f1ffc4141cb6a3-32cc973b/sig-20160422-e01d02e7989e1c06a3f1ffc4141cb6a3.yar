rule sig_20160422_e01d02e7989e1c06a3f1ffc4141cb6a3 {
  meta:
    description = "datamaliciousorder - file 20160422_e01d02e7989e1c06a3f1ffc4141cb6a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6183ff89da1387e2a0ed7211e085662ebbcd2896478e082f52e79392d07717dc"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('n 5B(8x,2T,8w){g(2T){9 1:8 5T=8v;c(5T==\"8y\"){8 8" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}