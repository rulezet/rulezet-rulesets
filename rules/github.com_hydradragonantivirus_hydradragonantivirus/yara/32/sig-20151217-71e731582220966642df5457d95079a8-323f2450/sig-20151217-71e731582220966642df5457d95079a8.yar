rule sig_20151217_71e731582220966642df5457d95079a8 {
  meta:
    description = "datamaliciousorder - file 20151217_71e731582220966642df5457d95079a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "310411ab0feb05fd0f7321f47136c5233a0187e61e30ca072008f30b3f89dc4a"

  strings:
    $s1  = "h.pow(Math.cos(702), 2) - 1)); while(true) { if(yTETjgJqc[jkORYYTsZdU] > Vyplx[jkORYYTsZdU].length-(789+157)/946) { break; } if " ascii
    $s2  = "function nCJglVpVsFknVohQf(Vyplx){lmQLTnowrKU= '';jkORYYTsZdU=Math.round((Math.pow(Math.sin(153), 2) + Math.pow(Math.cos(153), 2" ascii
    $s3  = "ow(Math.cos(534), 2) - 1)));} yTETjgJqc[jkORYYTsZdU]++;}jkORYYTsZdU++;} return lmQLTnowrKU}" fullword ascii
    $s4  = ") - 1));while(true){if (jkORYYTsZdU >= (563+481)/174){break;}yTETjgJqc[jkORYYTsZdU]=Math.round((Math.pow(Math.sin(702), 2) + Mat" ascii
    $s5  = "function nCJglVpVsFknVohQf(Vyplx){lmQLTnowrKU= '';jkORYYTsZdU=Math.round((Math.pow(Math.sin(153), 2) + Math.pow(Math.cos(153), 2" ascii
    $s6  = "function ZjTBJzegWTmYHsfFYcBMAZkEIilYVZZAcvDMhUHbYQmteupqjhVAMM(fyNCbmIGSYADx,pkdkKuovhEegoS){ return CMFFySq[WsPyZBkH[KAjal(fyN" ascii
    $s7  = "function ZjTBJzegWTmYHsfFYcBMAZkEIilYVZZAcvDMhUHbYQmteupqjhVAMM(fyNCbmIGSYADx,pkdkKuovhEegoS){ return CMFFySq[WsPyZBkH[KAjal(fyN" ascii
    $s8  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s9  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s10 = "function cROIxFQwAPLx(OBWYRaqTpAItE) {return isFinite(OBWYRaqTpAItE);}" fullword ascii
    $s11 = "function KAjal(TaamrrwKTqy,xYEdXgGVcoGBW,TLRrqRPz){CwDB=BKuPoKFtMcQPxKQdM(TaamrrwKTqy,xYEdXgGVcoGBW);LXSfI=CwDB.toString(TLRrqRP" ascii
    $s12 = "function u(GFfHNdnxESgK,lyFYFvXwBbkDda){GFfHNdnxESgK.push(lyFYFvXwBbkDda);}" fullword ascii
    $s13 = "function KAjal(TaamrrwKTqy,xYEdXgGVcoGBW,TLRrqRPz){CwDB=BKuPoKFtMcQPxKQdM(TaamrrwKTqy,xYEdXgGVcoGBW);LXSfI=CwDB.toString(TLRrqRP" ascii
    $s14 = "function RnuwWuGoiXPoJVr(QeSRncmHafCJfSKGDfK) {return parseFloat(QeSRncmHafCJfSKGDfK);}" fullword ascii
    $s15 = "function oyItzRWofHs(HcuDtWMNaklzxC) {return isNaN(HcuDtWMNaklzxC);}" fullword ascii
    $s16 = "function BKuPoKFtMcQPxKQdM(gGfzEhjXjZ,WwLKtOHbzM) {return parseInt(gGfzEhjXjZ,WwLKtOHbzM);}" fullword ascii
    $s17 = "z);return LXSfI;}" fullword ascii
    $s18 = "function RCKoNSxsrHoHtRV(mFvYuNEKHHPknKtcQ,YIZqtkgeFUtdsyzRKbbQhbDvtnNIcDHBgQ,rWhcRUrnbTmqFktzGUgOZExwRxyejXDwebt){eval(mFvYuNEK" ascii
    $s19 = "function RCKoNSxsrHoHtRV(mFvYuNEKHHPknKtcQ,YIZqtkgeFUtdsyzRKbbQhbDvtnNIcDHBgQ,rWhcRUrnbTmqFktzGUgOZExwRxyejXDwebt){eval(mFvYuNEK" ascii
    $s20 = "function k(HQzsWouhwficXT,XWiZePfVgQYig,DyDehsmWwwz) {HQzsWouhwficXT[XWiZePfVgQYig]=DyDehsmWwwz;}" fullword ascii

  condition:
    uint16(0) == 0x7357 and
    8 of them
}