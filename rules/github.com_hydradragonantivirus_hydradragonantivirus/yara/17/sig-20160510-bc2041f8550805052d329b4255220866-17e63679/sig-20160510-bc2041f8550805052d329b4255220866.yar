rule sig_20160510_bc2041f8550805052d329b4255220866 {
  meta:
    description = "datamaliciousorder - file 20160510_bc2041f8550805052d329b4255220866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b54e3bfc6ee2499ec1863512025d5ca50f8389819dafd9893f6013c4ab1329"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('b V(10,15){if(g1==fN){4 fO=\\'\\'}4 3S=1;if(5.o(3S" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}