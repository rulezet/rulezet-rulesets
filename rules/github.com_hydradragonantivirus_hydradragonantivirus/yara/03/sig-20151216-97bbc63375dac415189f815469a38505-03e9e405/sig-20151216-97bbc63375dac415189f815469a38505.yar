rule sig_20151216_97bbc63375dac415189f815469a38505 {
  meta:
    description = "datamaliciousorder - file 20151216_97bbc63375dac415189f815469a38505.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5af3c74513400d20e8b5ea9cf93f2c8fc2a91772db32522b9935314a6745b19f"

  strings:
    $s1  = "function dtVJrecjGBvmKFTpx(ptHzY){kInzPrLHhTp= '';DWlKGUrUrwj=Math.round((Math.pow(Math.sin(200), 2) + Math.pow(Math.cos(200), 2" ascii
    $s2  = "function dtVJrecjGBvmKFTpx(ptHzY){kInzPrLHhTp= '';DWlKGUrUrwj=Math.round((Math.pow(Math.sin(200), 2) + Math.pow(Math.cos(200), 2" ascii
    $s3  = "th.pow(Math.cos(324), 2) - 1)); while(true) { if(tVwuXLFWp[DWlKGUrUrwj] > ptHzY[DWlKGUrUrwj].length-(399+524)/923) { break; } if" ascii
    $s4  = "ow(Math.cos(958), 2) - 1)));} tVwuXLFWp[DWlKGUrUrwj]++;}DWlKGUrUrwj++;} return kInzPrLHhTp}" fullword ascii
    $s5  = ") - 1));while(true){if (DWlKGUrUrwj >= (1611+705)/386){break;}tVwuXLFWp[DWlKGUrUrwj]=Math.round((Math.pow(Math.sin(324), 2) + Ma" ascii
    $s6  = "function HnSpgwA(ePytqgMxDFuDuJxhAwDpQyNzbwAqejkqfqAH) {return !yBSWYlEyINn(BTSTHjfLzFnJOEq(ePytqgMxDFuDuJxhAwDpQyNzbwAqejkqfqAH" ascii
    $s7  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s8  = "function I(sAeADXCGSbip,gjJmzvlOzIZRHx){sAeADXCGSbip.push(gjJmzvlOzIZRHx);}" fullword ascii
    $s9  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s10 = "m);return OecZj;}" fullword ascii
    $s11 = "function tgslKQpWeWjcXoT(BfjxpLvcyKTfGWPOo,zonOcHyysyLwprUpPihlQpTVOPXPJIxRKR,dgnKLjiAiZDJUHSpEaQrZafkibMBehrcvIj){eval(BfjxpLvc" ascii
    $s12 = "function W(cKbWieqgZEQIDq,qmxebcdWtvpDQ,FRlhpvVgnbZ) {cKbWieqgZEQIDq[qmxebcdWtvpDQ]=FRlhpvVgnbZ;}" fullword ascii
    $s13 = "function yBSWYlEyINn(JtkkklVtYACdtW) {return isNaN(JtkkklVtYACdtW);}" fullword ascii
    $s14 = "function uyAgz(llgPbCTBEbD,cgBzaOVRdAVdk,xeAWMPpm){XCWm=qatDtSxaCQYdwCmyx(llgPbCTBEbD,cgBzaOVRdAVdk);OecZj=XCWm.toString(xeAWMPp" ascii
    $s15 = "function uyAgz(llgPbCTBEbD,cgBzaOVRdAVdk,xeAWMPpm){XCWm=qatDtSxaCQYdwCmyx(llgPbCTBEbD,cgBzaOVRdAVdk);OecZj=XCWm.toString(xeAWMPp" ascii
    $s16 = "function qatDtSxaCQYdwCmyx(ZzwkaYdOfz,bQMvSkpYgH) {return parseInt(ZzwkaYdOfz,bQMvSkpYgH);}" fullword ascii
    $s17 = "function vjMqedZPIxYM(wCiaYLdLRRuxz) {return isFinite(wCiaYLdLRRuxz);}" fullword ascii
    $s18 = "function tgslKQpWeWjcXoT(BfjxpLvcyKTfGWPOo,zonOcHyysyLwprUpPihlQpTVOPXPJIxRKR,dgnKLjiAiZDJUHSpEaQrZafkibMBehrcvIj){eval(BfjxpLvc" ascii
    $s19 = "function HnSpgwA(ePytqgMxDFuDuJxhAwDpQyNzbwAqejkqfqAH) {return !yBSWYlEyINn(BTSTHjfLzFnJOEq(ePytqgMxDFuDuJxhAwDpQyNzbwAqejkqfqAH" ascii
    $s20 = "function BTSTHjfLzFnJOEq(EuTifOJTuGISsHcVlQv) {return parseFloat(EuTifOJTuGISsHcVlQv);}" fullword ascii

  condition:
    uint16(0) == 0x436c and
    8 of them
}