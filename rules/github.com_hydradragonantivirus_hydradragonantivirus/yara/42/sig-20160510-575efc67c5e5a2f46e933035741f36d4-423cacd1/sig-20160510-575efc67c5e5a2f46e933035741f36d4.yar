rule sig_20160510_575efc67c5e5a2f46e933035741f36d4 {
  meta:
    description = "datamaliciousorder - file 20160510_575efc67c5e5a2f46e933035741f36d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b8d88d0fda476d6849604a10465f77caa023eefdb229125b9d2124e5faf82b1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c 1f(dE){if(\"9y\".M(\"\\\\F\\\\l\\\\l\\\\S\\\\u" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}