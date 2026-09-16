rule sig_20160512_89e8c28922befe950f68b7fc5e87d94d {
  meta:
    description = "datamaliciousorder - file 20160512_89e8c28922befe950f68b7fc5e87d94d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6f8e1496a44f7cd17c777022c2bc545d00286bc3ad7aea9ab320d10cc4849be"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 2I(){3 28=\"f\";5 28}4 s(){3 2b=\"r\";5 2b}4 J()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}