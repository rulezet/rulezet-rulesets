rule sig_20160512_3d8cc8cfd5dc04c08acd7b829ee9ba98 {
  meta:
    description = "datamaliciousorder - file 20160512_3d8cc8cfd5dc04c08acd7b829ee9ba98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeed05b04abacbd8fbda3dd5205aeb89f20f3fa6ddcace9fbe6f5c70f0672d6a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 20(){3 1g=\"f\";5 1g}4 p(){3 1h=\"r\";5 1h}4 w()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}