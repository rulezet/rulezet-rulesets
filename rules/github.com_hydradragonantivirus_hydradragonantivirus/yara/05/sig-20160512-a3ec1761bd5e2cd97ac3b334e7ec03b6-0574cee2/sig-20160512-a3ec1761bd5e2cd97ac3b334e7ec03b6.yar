rule sig_20160512_a3ec1761bd5e2cd97ac3b334e7ec03b6 {
  meta:
    description = "datamaliciousorder - file 20160512_a3ec1761bd5e2cd97ac3b334e7ec03b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2a6cb57161df131baa101c7c89b99ae675419d53b458d6b375ab6eab46b457a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('4 26(){3 1J=\"f\";5 1J}4 q(){3 1I=\"r\";5 1I}4 J()" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}