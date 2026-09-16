rule sig_20160422_6fffe2da7d412b970366866ee4f5c6e8 {
  meta:
    description = "datamaliciousorder - file 20160422_6fffe2da7d412b970366866ee4f5c6e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24aeb4d559a25df7e910c1150ca3367aa525b332ba119191f99e6695636e279"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j 4n(){8 6V=f;8 4p=\"6U\";e(4p==f){8 6W=f;8 6X=f;g" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}