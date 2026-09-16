rule sig_20160510_c14666f09abb29fd7ea0738fb2e9b328 {
  meta:
    description = "datamaliciousorder - file 20160510_c14666f09abb29fd7ea0738fb2e9b328.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e320ae8a30007b659fa1839a1bf69b42dbc6cc30429f3fcde97d91edca3796e2"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('c g(11,T,n,19){if(9u<=-9v){4 9t=-9s}if(\"9p\".Q(\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}