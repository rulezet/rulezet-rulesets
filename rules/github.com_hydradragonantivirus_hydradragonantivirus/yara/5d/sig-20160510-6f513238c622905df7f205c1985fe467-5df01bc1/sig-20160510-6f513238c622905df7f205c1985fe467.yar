rule sig_20160510_6f513238c622905df7f205c1985fe467 {
  meta:
    description = "datamaliciousorder - file 20160510_6f513238c622905df7f205c1985fe467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d833468e9eb9ebd5e7708e7c2a2e5e884c5737ca15b86126046945f116d0e11"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b kQ(N,15){4 2I=1;if(5.x(2I)>=0){9A=\"-9B\"}if(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}