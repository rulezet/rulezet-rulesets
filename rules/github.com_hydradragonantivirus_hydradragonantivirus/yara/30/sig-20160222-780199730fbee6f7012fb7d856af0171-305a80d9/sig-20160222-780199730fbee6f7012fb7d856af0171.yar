rule sig_20160222_780199730fbee6f7012fb7d856af0171 {
  meta:
    description = "datamaliciousorder - file 20160222_780199730fbee6f7012fb7d856af0171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ae8f5b1be150a84259c7236ec0f5801c8df8a671acca5c4cbfdacafd9af87bb"

  strings:
    $s1 = "eval((function(){var d=[94,74,88,87,72,65,60,70,79,81,89,85,86,76,80,71,82,75,90,66];var e=[];for(var b=0;b<d.length;b++)e[d[b]]" ascii
    $s2 = "plit('@'+x.charAt(b)).join(String.fromCharCode(c[b]));return r.split('@!').join('@');})('^&a;(function(){function @ox$(str,rnd){" ascii
    $s3 = "%261494)^%f=d%c^%g=e%c^%h=a[f];a[f]=a[g];a[g]=h;rnd=(d+e)%47440642;}^%s=String.fromCharCode(127);return a^!@d@d^ @d%@d)^!s^ @d#1" ascii
    $s4 = "eval((function(){var d=[94,74,88,87,72,65,60,70,79,81,89,85,86,76,80,71,82,75,90,66];var e=[];for(var b=0;b<d.length;b++)e[d[b]]" ascii
    $s5 = "(n+1)-32;m=n;n++;}else if(o==96){h=94*d.length+(i.charCodeAt(n+1)-32)*94+i.charCodeAt(n+2)-32;m=n;n+=2;}else{continue;}if(j==nul" ascii
    $s6 = "@d)^!@d%@d^ @d#0@d)^!@d#@d^ s);}return eval(@ox$(\"d(rfn{n)yir^#e:t;v@zedee$r]in.#rn50[18+o0tnu2)e=uic[i }.mllp;ne10 rang;b#e)@w" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}