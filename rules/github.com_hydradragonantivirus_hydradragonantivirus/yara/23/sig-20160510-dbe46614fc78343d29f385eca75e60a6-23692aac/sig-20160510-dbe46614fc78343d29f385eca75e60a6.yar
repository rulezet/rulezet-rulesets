rule sig_20160510_dbe46614fc78343d29f385eca75e60a6 {
  meta:
    description = "datamaliciousorder - file 20160510_dbe46614fc78343d29f385eca75e60a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05feed95fb8db97b2cb254154673dfa66d576af32d39990d186c5334bf7e6f52"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('f hx(Z,14){4 4B=-1;if(5.G(4B)==0){4 fL=\\'\\'}6{4 " ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}