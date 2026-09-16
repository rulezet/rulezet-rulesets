rule sig_20151210_6fd32a5c53d0475f62a08b969f9c12b3 {
  meta:
    description = "datamaliciousorder - file 20151210_6fd32a5c53d0475f62a08b969f9c12b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2dc4b8d2aa24fc9b5b8031c8d163eeeee5c0b4ac679ef2efbb40778ab19b1ef"

  strings:
    $s1  = "function tmwRvBH(phhsSGgCoERsQNiIijhfGesqvhWztTPlzjUP) {return !isNaN(parseFloat(phhsSGgCoERsQNiIijhfGesqvhWztTPlzjUP)) && isFin" ascii
    $s2  = "function tmwRvBH(phhsSGgCoERsQNiIijhfGesqvhWztTPlzjUP) {return !isNaN(parseFloat(phhsSGgCoERsQNiIijhfGesqvhWztTPlzjUP)) && isFin" ascii
    $s3  = "function QfHdRcnqjEmMgKMNvQaJImvxNAJUydrLDvIyeWCmzyUgFuwWNDkErL(gLoUxTIzEzFOm,fxSbpiWKDrEAVa){ return YjtJmHSAsoCEF[GTepT(gLoUxT" ascii
    $s4  = "function ndzAnjGWsfpBFtBIb(Hmeix){XHzXSNOBNod= '';for(SxLiUmWvFnT=(-724+724)/307; SxLiUmWvFnT < (1476+500)/988; SxLiUmWvFnT++) {" ascii
    $s5  = "function nONEbkanInx(wIyJSIYY,biQppA){return wIyJSIYY.split(biQppA)}" fullword ascii
    $s6  = "function GTepT(UdPlUHpqjAC,ZbulWiKdmROrj,OKRIwKzl){bfae=parseInt(UdPlUHpqjAC,ZbulWiKdmROrj);fenoP=bfae.toString(OKRIwKzl);return" ascii
    $s7  = "]++;}} return XHzXSNOBNod}" fullword ascii
    $s8  = " fenoP;}function BsZxiKEnbjeRyyO(AmeRIVjTZxtHFNzyp){eval(AmeRIVjTZxtHFNzyp)}" fullword ascii
    $s9  = "function QfHdRcnqjEmMgKMNvQaJImvxNAJUydrLDvIyeWCmzyUgFuwWNDkErL(gLoUxTIzEzFOm,fxSbpiWKDrEAVa){ return YjtJmHSAsoCEF[GTepT(gLoUxT" ascii
    $s10 = "function GTepT(UdPlUHpqjAC,ZbulWiKdmROrj,OKRIwKzl){bfae=parseInt(UdPlUHpqjAC,ZbulWiKdmROrj);fenoP=bfae.toString(OKRIwKzl);return" ascii
    $s11 = "faBfaMU=(-766+766)/907;while(true){if(faBfaMU>=(78511+849)/620){break;}YjtJmHSAsoCEF[faBfaMU]=String.fromCharCode(faBfaMU);faBfa" ascii
    $s12 = "faBfaMU=(-766+766)/907;while(true){if(faBfaMU>=(78511+849)/620){break;}YjtJmHSAsoCEF[faBfaMU]=String.fromCharCode(faBfaMU);faBfa" ascii
    $s13 = "BLwcySYgw[SxLiUmWvFnT]=(-854+854)/767; while(true) { if(BLwcySYgw[SxLiUmWvFnT] > Hmeix[SxLiUmWvFnT].length-(261+704)/965) { brea" ascii
    $s14 = "function ndzAnjGWsfpBFtBIb(Hmeix){XHzXSNOBNod= '';for(SxLiUmWvFnT=(-724+724)/307; SxLiUmWvFnT < (1476+500)/988; SxLiUmWvFnT++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}