rule sig_20151217_9c7d902bdef8ce65fc13ab09a9b513dd {
  meta:
    description = "datamaliciousorder - file 20151217_9c7d902bdef8ce65fc13ab09a9b513dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc8abd9ee5f2002b454aaa7f52c7fc96267e02fb602cb76128eca83173449132"

  strings:
    $s1  = ".pow(Math.cos(399), 2) - 1)); while(true) { if(TksgmKhAr[rTnBgrkMzBT] > cWXxP[rTnBgrkMzBT].length-(-506+918)/412) { break; } if " ascii
    $s2  = "w(Math.cos(976), 2) - 1)));} TksgmKhAr[rTnBgrkMzBT]++;}rTnBgrkMzBT++;} return ytQinETfuDP}" fullword ascii
    $s3  = "function mfbimEJGHXPrRiEoG(cWXxP){ytQinETfuDP= '';rTnBgrkMzBT=Math.round((Math.pow(Math.sin(65), 2) + Math.pow(Math.cos(65), 2) " ascii
    $s4  = "function mfbimEJGHXPrRiEoG(cWXxP){ytQinETfuDP= '';rTnBgrkMzBT=Math.round((Math.pow(Math.sin(65), 2) + Math.pow(Math.cos(65), 2) " ascii
    $s5  = "- 1));while(true){if (rTnBgrkMzBT >= (-307+961)/109){break;}TksgmKhAr[rTnBgrkMzBT]=Math.round((Math.pow(Math.sin(399), 2) + Math" ascii
    $s6  = "function xbQYVRXPpQTcpux(QkpOPOuLhkcgFzira,URmdEVShichcfGbBKdDWwPvCIJwjOeWluo,IexzdirCYbObKYdEUhaTFBYXBvrKoFyiDOO){eval(QkpOPOuL" ascii
    $s7  = "function xbQYVRXPpQTcpux(QkpOPOuLhkcgFzira,URmdEVShichcfGbBKdDWwPvCIJwjOeWluo,IexzdirCYbObKYdEUhaTFBYXBvrKoFyiDOO){eval(QkpOPOuL" ascii
    $s8  = "function YxlLcDP(LmUGoJGSbtmSNaPsdDgvUUZeRZGCVvYOIcWt) {return !LXwgAFHhKFs(LAKlwqewVrqxQlk(LmUGoJGSbtmSNaPsdDgvUUZeRZGCVvYOIcWt" ascii
    $s9  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s10 = "function dVvTkmCvLkBrXPCQvFepbBuTlLhfkVJfchIkgBXTEVPFYkVAwsvzgF(KClXMAvKQPhMw,WUAqqFYuuBPKDS){ return eoLYBzC[UyDadZAt[Dhhcl(KCl" ascii
    $s11 = "function b(vBmvFEYOddwi,UnZStlpPPgFQkA){vBmvFEYOddwi.push(UnZStlpPPgFQkA);}" fullword ascii
    $s12 = "D);return xZdYW;}" fullword ascii
    $s13 = "function vHgALfvkKWvw(qlGLlPtnaGZww) {return isFinite(qlGLlPtnaGZww);}" fullword ascii
    $s14 = "function LXwgAFHhKFs(QTLZTCTdqIivjZ) {return isNaN(QTLZTCTdqIivjZ);}" fullword ascii
    $s15 = "function D(iJMfekTHIrQxsd,hmLRzuotPDQfR,QALSVlumACS) {iJMfekTHIrQxsd[hmLRzuotPDQfR]=QALSVlumACS;}" fullword ascii
    $s16 = "function GrInrkciJwzpNDLPp(aejMYUGvUH,eYdGxzkjDk) {return parseInt(aejMYUGvUH,eYdGxzkjDk);}" fullword ascii
    $s17 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s18 = "function YxlLcDP(LmUGoJGSbtmSNaPsdDgvUUZeRZGCVvYOIcWt) {return !LXwgAFHhKFs(LAKlwqewVrqxQlk(LmUGoJGSbtmSNaPsdDgvUUZeRZGCVvYOIcWt" ascii
    $s19 = "function LAKlwqewVrqxQlk(NqiSYBgDYOguFVAzNDt) {return parseFloat(NqiSYBgDYOguFVAzNDt);}" fullword ascii
    $s20 = "function dVvTkmCvLkBrXPCQvFepbBuTlLhfkVJfchIkgBXTEVPFYkVAwsvzgF(KClXMAvKQPhMw,WUAqqFYuuBPKDS){ return eoLYBzC[UyDadZAt[Dhhcl(KCl" ascii

  condition:
    uint16(0) == 0x7955 and
    8 of them
}