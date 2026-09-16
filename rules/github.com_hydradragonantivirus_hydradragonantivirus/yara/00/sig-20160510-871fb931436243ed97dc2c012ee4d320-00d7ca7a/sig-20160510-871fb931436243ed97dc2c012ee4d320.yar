rule sig_20160510_871fb931436243ed97dc2c012ee4d320 {
  meta:
    description = "datamaliciousorder - file 20160510_871fb931436243ed97dc2c012ee4d320.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a7805e0f5d58f34595b67e198172089d8cfd956c726b6fd6e64d635abb078c0"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('9 9k(3I,3Q){if(9l>9j){4 9i=\"\"}6{4 9f=9g}9 9h(gx)" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}