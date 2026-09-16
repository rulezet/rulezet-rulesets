rule sig_20160520_21c5d89a0261ad3fc084ba154859a0d6 {
  meta:
    description = "datamaliciousorder - file 20160520_21c5d89a0261ad3fc084ba154859a0d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4496c9b3dbf356c94a6d88653975f5c1004daa4a4ad5e1ef3b13ca8ec1ebd1fa"

  strings:
    $s1  = "function qnPPBkAV(tMpFE) {var nFatDvKx=lCqxi[2];for(var bjNcy=0;bjNcy<tMpFE;bjNcy++){UPSna+=nFatDvKx.charAt(Math.floor(Math.rand" ascii
    $s2  = "function qnPPBkAV(tMpFE) {var nFatDvKx=lCqxi[2];for(var bjNcy=0;bjNcy<tMpFE;bjNcy++){UPSna+=nFatDvKx.charAt(Math.floor(Math.rand" ascii
    $s3  = "function qvYuu(LDTgHlXk,BvLSle,OQcMloTqH){xlTji=LDTgHlXk.split(OQcMloTqH);xUwYtkg = lCqxi[13];for(YbqggsJo=0;YbqggsJo<BvLSle.len" ascii
    $s4  = "function PSsY(bLwkez,dtQgTmE){gWYl = lCqxi[11].split(lCqxi[12]);dtQgTmE.open(gWYl[0]+gWYl[2]+gWYl[3], bLwkez, false);dtQgTmE.sen" ascii
    $s5  = "try{JEKRlvCYe(zAKOJ[VHiB], ZZpHZRk() + lCqxi[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function ZZpHZRk() {var PHxs=100000;var iABeiK = 100;return Math.random()*(PHxs-iABeiK)+iABeiK;}" fullword ascii
    $s7  = "function ILUGJ(uFqGjMWR,CtJiz,fpXxcZcvNy){uFqGjMWR.open();uFqGjMWR.type = 1;uFqGjMWR.write(CtJiz);uFqGjMWR.position = 0;uFqGjMWR" ascii
    $s8  = "function ILUGJ(uFqGjMWR,CtJiz,fpXxcZcvNy){uFqGjMWR.open();uFqGjMWR.type = 1;uFqGjMWR.write(CtJiz);uFqGjMWR.position = 0;uFqGjMWR" ascii
    $s9  = "function qvYuu(LDTgHlXk,BvLSle,OQcMloTqH){xlTji=LDTgHlXk.split(OQcMloTqH);xUwYtkg = lCqxi[13];for(YbqggsJo=0;YbqggsJo<BvLSle.len" ascii
    $s10 = "function gPeYA(xSkozw){return new ActiveXObject(xSkozw);}" fullword ascii
    $s11 = "function PSsY(bLwkez,dtQgTmE){gWYl = lCqxi[11].split(lCqxi[12]);dtQgTmE.open(gWYl[0]+gWYl[2]+gWYl[3], bLwkez, false);dtQgTmE.sen" ascii
    $s12 = "om()*nFatDvKx.length));}return UPSna;}" fullword ascii
    $s13 = "gth;YbqggsJo++) {xUwYtkg+=xlTji[BvLSle[YbqggsJo]];}return xUwYtkg.substring(3,xUwYtkg.length);}" fullword ascii
    $s14 = "function NimpNt(xSkozw){return xSkozw.ExpandEnvironmentStrings(lCqxi[10])}" fullword ascii
    $s15 = "function JEKRlvCYe(sfuvGkcOW,lwnAXAy,dPMAQCeX){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}