rule sig_20170426_6d9bc15df6dc1f12c4d0fa4773c99be9 {
  meta:
    description = "datamaliciousorder - file 20170426_6d9bc15df6dc1f12c4d0fa4773c99be9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9e469993c7e256fe99d84a99c74c4580a917fa8980db032b3441a293ae6d8c8"

  strings:
    $s1  = "effecfcffec.Run(fecebbeadfeac('----1P1O1XvQ1qS@1qv+vp1Pv+',1)+ cdbfebedcfdfd +'\\\\'+ fecebbeadfeac('----1PPX1211vQ1qS@1q',1),0," ascii
    $s2  = "WScript.echo('Runtime Error 0x48940 (.QBT) Library not located on the system, please use x64 system.');" fullword ascii
    $s3  = "  return !isNaN(parseFloat(cfcccdebebeadadfeb)) && isFinite(cfcccdebebeadadfeb);" fullword ascii
    $s4  = "function bfedfedeeaacefdfbe(sstrstrtbabececcfer,eeeabbecba){" fullword ascii
    $s5  = "return fdceffbbbfceeeacd;" fullword ascii
    $s6  = "fdbbccbfdeabad = String.fromCharCode.apply(String, baeeabcbfaab);" fullword ascii
    $s7  = "function ebefdaddfefd(babececcfebabececcfe,decbbabcdc){" fullword ascii
    $s8  = "function befddbadfafded(affefbbeeaddceb) {" fullword ascii
    $s9  = "return befddbadfafded(fceddfaafacdcb);" fullword ascii
    $s10 = "function fecebbeadfeac(dfadaceeaacc,bedbadafddeddfdf){" fullword ascii
    $s11 = "function edbaabffdeef(fbcbdabfd){ " fullword ascii
    $s12 = "if(acdcedbeeafdaccbd.Status == 200)break;" fullword ascii
    $s13 = "return ddaccdaabcedcefd;" fullword ascii
    $s14 = "var size = dfadaceeaacc.length;" fullword ascii
    $s15 = "return babececcfebabececcfe;" fullword ascii
    $s16 = "acdcedbeeafdaccbd.open(fecebbeadfeac('----XSXqqX',1), fecebbeadfeac('----1@SXSXS+PWvpvp1@1pSv1P1pSvvQ1P1p1Ovp1S12SX1qvQS+1@S+',1" ascii
    $s17 = ")+'?ff'+dfbeafeccca, false);" fullword ascii
    $s18 = " if(dadfaccabf == true){" fullword ascii
    $s19 = "function bfddcade(){" fullword ascii
    $s20 = "for(var fffbaceeebcab = 0; fffbaceeebcab<size ; fffbaceeebcab++){" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}