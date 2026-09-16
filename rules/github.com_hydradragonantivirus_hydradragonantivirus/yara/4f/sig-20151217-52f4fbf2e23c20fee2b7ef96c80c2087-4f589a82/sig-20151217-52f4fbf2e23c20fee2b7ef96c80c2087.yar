rule sig_20151217_52f4fbf2e23c20fee2b7ef96c80c2087 {
  meta:
    description = "datamaliciousorder - file 20151217_52f4fbf2e23c20fee2b7ef96c80c2087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4af48d5019cdc684741f815f1ee742997f03af2786b9187f3cba585668dc2bf"

  strings:
    $s1  = ") - 1));while(true){if (vTYkYhxWZfC >= (2158+974)/522){break;}rNUhAemHn[vTYkYhxWZfC]=Math.round((Math.pow(Math.sin(921), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(921), 2) - 1)); while(true) { if(rNUhAemHn[vTYkYhxWZfC] > cQJVc[vTYkYhxWZfC].length-(-412+818)/406) { break; } i" ascii
    $s3  = ".pow(Math.cos(633), 2) - 1)));} rNUhAemHn[vTYkYhxWZfC]++;}vTYkYhxWZfC++;} return yLCINCoKuPg}" fullword ascii
    $s4  = "function rWhxNXHffqFzGvzGv(cQJVc){yLCINCoKuPg= '';vTYkYhxWZfC=Math.round((Math.pow(Math.sin(488), 2) + Math.pow(Math.cos(488), 2" ascii
    $s5  = "WnuRbmSICwLUzLWdrNvDCOHMLHKjSRCvHoPW([cQJVc[vTYkYhxWZfC][rNUhAemHn[vTYkYhxWZfC]]], Math.round((Math.pow(Math.sin(633), 2) + Math" ascii
    $s6  = "function rWhxNXHffqFzGvzGv(cQJVc){yLCINCoKuPg= '';vTYkYhxWZfC=Math.round((Math.pow(Math.sin(488), 2) + Math.pow(Math.cos(488), 2" ascii
    $s7  = "function MLIReTt(YFgIVaiVyeTUdZjUhdyNbOsCeIJjpswxjiHl) {return !DpUfVvSlcrw(olzjSbiHpbmCuYD(YFgIVaiVyeTUdZjUhdyNbOsCeIJjpswxjiHl" ascii
    $s8  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s9  = "function t(QFpJcJljjvOe,ZWoYipMHVFyZiP){QFpJcJljjvOe.push(ZWoYipMHVFyZiP);}" fullword ascii
    $s10 = "function FZlWwuEXhVXBdZi(DWluWprbbOFHogskq,rbPocWOYTCtIwtfNZNbmXYDdZsCOFnVXsT,XMGFQKkytMnFkJWVXPrreiBdhZnVWtofxOl){eval(DWluWprb" ascii
    $s11 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s12 = "function lbwdTjPruAWsgkRdn(WlefPYaXhh,hQkWKjnxnU) {return parseInt(WlefPYaXhh,hQkWKjnxnU);}" fullword ascii
    $s13 = "b);return dNznk;}" fullword ascii
    $s14 = "function grJDAImmmoUL(HxOabYZzDsIHc) {return isFinite(HxOabYZzDsIHc);}" fullword ascii
    $s15 = "function DpUfVvSlcrw(vpPWRULGasPryW) {return isNaN(vpPWRULGasPryW);}" fullword ascii
    $s16 = "function FZlWwuEXhVXBdZi(DWluWprbbOFHogskq,rbPocWOYTCtIwtfNZNbmXYDdZsCOFnVXsT,XMGFQKkytMnFkJWVXPrreiBdhZnVWtofxOl){eval(DWluWprb" ascii
    $s17 = "function olzjSbiHpbmCuYD(NivloQzbcRyrALrcXZz) {return parseFloat(NivloQzbcRyrALrcXZz);}" fullword ascii
    $s18 = "function ioOHz(NRgIyMtdlpc,DUvcENyFppKoC,UXfUtRQb){DEpJ=lbwdTjPruAWsgkRdn(NRgIyMtdlpc,DUvcENyFppKoC);dNznk=DEpJ.toString(UXfUtRQ" ascii
    $s19 = "function ioOHz(NRgIyMtdlpc,DUvcENyFppKoC,UXfUtRQb){DEpJ=lbwdTjPruAWsgkRdn(NRgIyMtdlpc,DUvcENyFppKoC);dNznk=DEpJ.toString(UXfUtRQ" ascii
    $s20 = "function MLIReTt(YFgIVaiVyeTUdZjUhdyNbOsCeIJjpswxjiHl) {return !DpUfVvSlcrw(olzjSbiHpbmCuYD(YFgIVaiVyeTUdZjUhdyNbOsCeIJjpswxjiHl" ascii

  condition:
    uint16(0) == 0x5676 and
    8 of them
}