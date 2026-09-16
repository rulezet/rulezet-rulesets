rule sig_20160510_a94dc6066d0414a4acb1a988ebfd8148 {
  meta:
    description = "datamaliciousorder - file 20160510_a94dc6066d0414a4acb1a988ebfd8148.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a807f51abf94e710a1f29c369e1d831d944d0f9cf1dc48c06830206b2c544d3"

  strings:
    $x1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('9 3A(1b,A){4 E=0;if(6.11(E)>0){u=\"9I\"}5{9J=d}4 3" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}