rule sig_20170403_5cc0758c10bcfc404fa32b99af73bcee {
  meta:
    description = "datamaliciousorder - file 20170403_5cc0758c10bcfc404fa32b99af73bcee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a62712ff422477b15e512d3d83285d61c760c468e8f8bae26a7e5f0174e57db9"

  strings:
    $x1 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e" ascii
    $s2 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e" ascii
    $s3 = "]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('1 2" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and all of them
}