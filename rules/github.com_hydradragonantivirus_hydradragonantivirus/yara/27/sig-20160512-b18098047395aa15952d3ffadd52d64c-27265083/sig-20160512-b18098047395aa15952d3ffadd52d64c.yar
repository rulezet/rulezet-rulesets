rule sig_20160512_b18098047395aa15952d3ffadd52d64c {
  meta:
    description = "datamaliciousorder - file 20160512_b18098047395aa15952d3ffadd52d64c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0408c8d327d357fc53abc40bc11c7412a2f87c931a2d17757d4928b1c5b1007e"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 1F(){3 1i=\"f\";5 1i}4 q(){3 1q=\"r\";5 1q}4 x()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}