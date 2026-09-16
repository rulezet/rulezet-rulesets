rule sig_20160422_2df0a4102b3d6adb0a39deb8a30c4a79 {
  meta:
    description = "datamaliciousorder - file 20160422_2df0a4102b3d6adb0a39deb8a30c4a79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "475a8e7b677b2993588ad720cda32158706e5285d17bf7092fe38a8cdbb78bc6"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('g 4b(1U,6i,6j,6k){7 6l=6h;8(1U==0){7 6c=e;j(\"6d\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}