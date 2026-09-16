rule sig_20160510_97244db2bd737da9be8649a715cf3667 {
  meta:
    description = "datamaliciousorder - file 20160510_97244db2bd737da9be8649a715cf3667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1f20512736d3995f424306ba976fa5e6e5f02fce11d8349da9a991dae7eea1"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};" ascii
    $s2 = "){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('i 9u(3Q,kZ){i 9v(Q){l 5.1g(Q)}if(\"9t\".h<9s){4 T=" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}