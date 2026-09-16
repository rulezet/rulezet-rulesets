rule sig_20160510_3007b7bed7f041f90858481e4981d1be {
  meta:
    description = "datamaliciousorder - file 20160510_3007b7bed7f041f90858481e4981d1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa62160dda1d8632b76fcba2cfb316d43f0a46ee267905d61ade17391bd35580"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('j dv(){4 4u=-1;if(6.17(4u)==0){4 9L=7(9M)}5{4 h=\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}