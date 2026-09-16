rule sig_20160510_ee0c13397b81d9a50e612c50719baec1 {
  meta:
    description = "datamaliciousorder - file 20160510_ee0c13397b81d9a50e612c50719baec1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "676173f5ac4ce5786762fc68b345e5b8a4e1ae30e69fa557ee9071d7413293dd"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('l 1b(1e,d){if(\"\".s>-9S){4 kd=\\'9T\\'}4 kk=1;if(" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}