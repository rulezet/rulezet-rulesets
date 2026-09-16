rule sig_20160510_d836b5acc3df967c3099a66d402fba06 {
  meta:
    description = "datamaliciousorder - file 20160510_d836b5acc3df967c3099a66d402fba06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83599ab474ffb574855f608b4a327833c2f107b9d01545186e6afccb3092a97a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('n 24(Z,12,e,1n){4 43=0;if(6.t(43)===0){4 Y=\\'\\'}" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}