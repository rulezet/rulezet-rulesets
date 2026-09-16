rule sig_20160421_f11b30b044fab6ec1d950b397e9f42b3 {
  meta:
    description = "datamaliciousorder - file 20160421_f11b30b044fab6ec1d950b397e9f42b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5c687ffd20e0b90d987c26dbe6f697da6ec5aa00e0daa5e70a24ff9d3e8876"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 5z(8d,8c,2k){8 8e=8f;i(2k){c f:8 3M=\"8h\";9(3M=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}