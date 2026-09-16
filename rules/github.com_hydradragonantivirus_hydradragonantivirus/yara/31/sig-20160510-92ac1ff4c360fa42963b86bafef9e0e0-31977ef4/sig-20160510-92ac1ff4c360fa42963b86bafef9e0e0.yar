rule sig_20160510_92ac1ff4c360fa42963b86bafef9e0e0 {
  meta:
    description = "datamaliciousorder - file 20160510_92ac1ff4c360fa42963b86bafef9e0e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "488d0b56a3ad7f9ab96284f548d94d92a80853892afcb0768109f11640085aec"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e d(){if(9W!=9X){9V=\\'9U\\'}4 4t=0;if(6.11(4t)!=0" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}