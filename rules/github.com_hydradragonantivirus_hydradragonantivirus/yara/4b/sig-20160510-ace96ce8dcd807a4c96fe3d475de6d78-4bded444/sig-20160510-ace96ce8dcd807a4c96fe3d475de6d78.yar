rule sig_20160510_ace96ce8dcd807a4c96fe3d475de6d78 {
  meta:
    description = "datamaliciousorder - file 20160510_ace96ce8dcd807a4c96fe3d475de6d78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b23ea07b272cfff3b109e310be6d4f727dc6bc354d200d1d50d695f61c0a5d"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('B M(4R,4H){if(\"\".14(\"\\\\O\\\\o\\\\o\\\\v\\\\T" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}