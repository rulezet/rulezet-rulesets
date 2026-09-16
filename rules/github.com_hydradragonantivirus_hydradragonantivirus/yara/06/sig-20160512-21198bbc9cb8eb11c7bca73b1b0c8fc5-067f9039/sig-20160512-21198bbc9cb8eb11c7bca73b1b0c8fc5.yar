rule sig_20160512_21198bbc9cb8eb11c7bca73b1b0c8fc5 {
  meta:
    description = "datamaliciousorder - file 20160512_21198bbc9cb8eb11c7bca73b1b0c8fc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5931ee5225d44fa36541ad778f63dc0f42ce33f68811ce3d7e7c0e2428e482a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 21(){3 1D=\"f\";6 1D}4 n(){3 1C=\"r\";6 1C}4 y()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}