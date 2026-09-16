rule sig_20160510_b4439aa098ddaa1a7efc451601a4aa5c {
  meta:
    description = "datamaliciousorder - file 20160510_b4439aa098ddaa1a7efc451601a4aa5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeae10e2ab77cb3b5283d81b94d3c9e5edb5615ab4a91c8ef90c61a175b4de26"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d 9h(M,4v){d 9i(4j){e 5.P(4j)}if(\"9g\".O(\"-9f\")" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}