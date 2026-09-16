rule sig_20160523_292ab4ca50f17cfa6f4929c238e6c86f {
  meta:
    description = "datamaliciousorder - file 20160523_292ab4ca50f17cfa6f4929c238e6c86f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89921bcf08d9033dc065c21f0f87497d6203653cb2f1d2f71120af315c3f7035"

  strings:
    $s1  = "function GxAhodAUCS() {return/*PKpOoXkMeckmyTApogrVKJxZECblSzfLXqJQkBghkwLXxzchOPgUnTYnagyGtDgAibPCtuSdZlTojbpnXVoPaLREhjZvcxQWG" ascii
    $s2  = "function tUZFQjWoxL(OSebODnW,yqxksDMNYzfG) {OSebODnW.Run(yqxksDMNYzfG, 0x1, 0x0);}" fullword ascii
    $s3  = "function ZdzJUDXu(lJZfQ) {var qcnjVvhY=UOXIfWnbEazNUI[13];for(var OWSWH=0;OWSWH<lJZfQ;OWSWH++){WIseO+=qcnjVvhY.charAt(Math.floor" ascii
    $s4  = "function ZdzJUDXu(lJZfQ) {var qcnjVvhY=UOXIfWnbEazNUI[13];for(var OWSWH=0;OWSWH<lJZfQ;OWSWH++){WIseO+=qcnjVvhY.charAt(Math.floor" ascii
    $s5  = "INakM.length;MsrhuisF++) {pBolYZD+=FeOqk[PINakM[MsrhuisF]];}return pBolYZD.substring(3,pBolYZD.length);}" fullword ascii
    $s6  = "function mFfs(XPbvsd) {XPbvsd.open();}" fullword ascii
    $s7  = "function eRFE(vsDltYA,UjsnkVU) {vsDltYA.saveToFile(UjsnkVU, 2);}" fullword ascii
    $s8  = "function SEFRmqSwRVzEC() {GxAhodAUCS().Sleep(2368393-565);}" fullword ascii
    $s9  = "function YOTO(SFXxeQ,aPblCLB){htFB = UOXIfWnbEazNUI[10].split(UOXIfWnbEazNUI[11]);aPblCLB.open(htFB[0]+htFB[2]+htFB[3], SFXxeQ, " ascii
    $s10 = "function nwLAvHo(){return Math.random();}" fullword ascii
    $s11 = "false);aPblCLB.send();}" fullword ascii
    $s12 = "function GxAhodAUCS() {return/*PKpOoXkMeckmyTApogrVKJxZECblSzfLXqJQkBghkwLXxzchOPgUnTYnagyGtDgAibPCtuSdZlTojbpnXVoPaLREhjZvcxQWG" ascii
    $s13 = "function JIAEc(uEWTqLUd,PINakM,zEzbuxifk){FeOqk=uEWTqLUd.split(zEzbuxifk);pBolYZD = UOXIfWnbEazNUI[12];for(MsrhuisF=0;MsrhuisF<P" ascii
    $s14 = "function gdBznD(JDTSGk){return JDTSGk.ExpandEnvironmentStrings(UOXIfWnbEazNUI[9])}" fullword ascii
    $s15 = "function qzIQyuSCp(akuPdT) {var ifpJRHLAJf=[];akuPdT.position=ifpJRHLAJf.length*(9435877-744);}" fullword ascii
    $s16 = "function mtLVJwdU(wUwZRcyKl) {wUwZRcyKl.type=1;}" fullword ascii
    $s17 = "function ZJkFc(JDTSGk){return new ActiveXObject(JDTSGk);}" fullword ascii
    $s18 = "function bToKDHH(QqIl,fdLyJ) {QqIl.write(fdLyJ);}" fullword ascii
    $s19 = "function eqUPrXi(RGWzt) {RGWzt.close();}" fullword ascii
    $s20 = "function JIAEc(uEWTqLUd,PINakM,zEzbuxifk){FeOqk=uEWTqLUd.split(zEzbuxifk);pBolYZD = UOXIfWnbEazNUI[12];for(MsrhuisF=0;MsrhuisF<P" ascii

  condition:
    uint16(0) == 0x0e27 and
    8 of them
}