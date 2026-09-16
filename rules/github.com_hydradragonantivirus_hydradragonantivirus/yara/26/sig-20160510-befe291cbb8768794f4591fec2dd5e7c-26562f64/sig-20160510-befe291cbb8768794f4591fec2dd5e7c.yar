rule sig_20160510_befe291cbb8768794f4591fec2dd5e7c {
  meta:
    description = "datamaliciousorder - file 20160510_befe291cbb8768794f4591fec2dd5e7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3302b130317f6fa6f9ad619648bd21ab6eac59028880022f9732d4b0536c6a"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('d 1a(Z){if(9t<=9u){4 9v=9}4 bG=\"9s\";if(bG===\"\"" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}