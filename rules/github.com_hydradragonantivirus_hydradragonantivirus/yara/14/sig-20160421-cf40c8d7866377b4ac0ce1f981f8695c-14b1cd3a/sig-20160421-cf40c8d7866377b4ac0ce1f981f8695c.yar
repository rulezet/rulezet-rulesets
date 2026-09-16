rule sig_20160421_cf40c8d7866377b4ac0ce1f981f8695c {
  meta:
    description = "datamaliciousorder - file 20160421_cf40c8d7866377b4ac0ce1f981f8695c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4bc76067ffe02c94101e8034c1e5bc5244fb052643744d18d856c450a222782"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('h 1w(5T,5S){6 5R=b}h 4S(5k,2j,3Z){6 5U=\"5V\";f(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}