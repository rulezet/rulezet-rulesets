rule sig_20160510_aca7e6f3beef86a0f5bafcf1e67ef066 {
  meta:
    description = "datamaliciousorder - file 20160510_aca7e6f3beef86a0f5bafcf1e67ef066.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5d642d03f1933c3ee9f2514f3e6bf0bf636948cf8e0116505bc6bc5a421630c"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('e 1P(Q,10){e 9B(4S){g 5.14(4S)}if(\"9C\".M(\"\")>0" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}