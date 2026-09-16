rule sig_20160524_bd8feb25419e0ca17f3d9ba1d8093467 {
  meta:
    description = "datamaliciousorder - file 20160524_bd8feb25419e0ca17f3d9ba1d8093467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c98b6ac0e52a6524fc230b40cadc445ac83bbfc7a1ae66399e3ebd874e7f908"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "=function(){return new ActiveXObject(LYOKvxKl[0]);}();var ozAITTjf=function(){return new ActiveXObject(\"WScript.Shell\");}();va" ascii
    $s3  = "CTgmAjK, 2);}function lpJlqzf(ZakJU) {ZakJU.close();}function nZfmBZFUQN(UkDwkZMD,nGQnmWOgVnen) {UkDwkZMD.Run(nGQnmWOgVnen, 0x1," ascii
    $s4  = "e(92) + nfYZqRE;var ewmaa = function(){return new ActiveXObject(YSMCX(TSalyoKGmBf[5],[0,2,4],TSalyoKGmBf[6]));}();CKsY(EPdxsxnka" ascii
    $s5  = "{return new ActiveXObject(YSMCX(TSalyoKGmBf[3],[0,2,4],TSalyoKGmBf[4]));}();var nfYZqRE = EqLgSA(kxeFmyDgx) + String.fromCharCod" ascii
    $s6  = "v.length) break;var EPdxsxnka=NgFAv[rIzY];var nfYZqRE=rtbczfP() + TSalyoKGmBf[2];var pljwtdsq=843-842;var kxeFmyDgx = function()" ascii
    $s7  = "XZvPK.send();}function YSMCX(oSgHQmwb,fFQDkj,hlKJMzLpw){YlLjo=oSgHQmwb.split(hlKJMzLpw);kePbHkm = TSalyoKGmBf[12];for(pQPFhgsd=0" ascii
    $s8  = "wmfYkVpFJafhETbJftZQaQzIydzOmxxpBRrObDHqZyqBgTRzHIiPoiODlkGslhkozRyWMFTvjpvoCnBJcrlivTWRSLIqelRIrkx*/WScript;}function mdxiduHGS" ascii
    $s9  = "rIzY++;}function EqLgSA(JBjaYY){return JBjaYY.ExpandEnvironmentStrings(TSalyoKGmBf[9])}function pLCNU(aDowfHBA,Ngakj,RJhegZuJSW)" ascii
    $s10 = ";pQPFhgsd<fFQDkj.length;pQPFhgsd++) {kePbHkm+=YlLjo[fFQDkj[pQPFhgsd]];}return kePbHkm.substring(3,kePbHkm.length);}function yqaY" ascii
    $s11 = ";function (YyAXM) {return new ActiveXObject(YyAXM);}" fullword ascii
    $s12 = "on TCxGOWPB(UDHaHzjWb) {UDHaHzjWb.type=1;}function shGzkMV(bIKj,ePmmH) {bIKj.write(ePmmH);}function xwJlGRdhFp() {return/*lEghDI" ascii
    $s13 = "zSpscy;ajhxfV = iqXEjVG.OpenTextFile(VFKWwcW,2,true);ajhxfV.Write('var TSalyoKGmBf=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73" ascii
    $s14 = "51\\x6c\\x74\\x42\\x61\\x75\\x6a\\x76\\x74\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function PobGlWOQdVdAya() {" ascii
    $s15 = ";}return ZcfQl;}function qxEiNMLlUOStjG(iwETvOEHPmhzbi) {return new ActiveXObject(iwETvOEHPmhzbi);}');var SoqBlRlQvXWFtiL=[\"\\x" ascii
    $s16 = "(YjzKZU) {var MmjgQAOLKh=[];YjzKZU.position=MmjgQAOLKh.length*(6094348-640);}function ybTk(yTpqCHw,CTgmAjK) {yTpqCHw.saveToFile(" ascii
    $s17 = "ction CKsY(Ltydzu,CJXZvPK){TwUR = TSalyoKGmBf[10].split(TSalyoKGmBf[11]);CJXZvPK.open(TwUR[0]+TwUR[2]+TwUR[3], Ltydzu, false);CJ" ascii
    $s18 = "TmztvRafm() {xwJlGRdhFp().Sleep(3775-436);}function sjRYzco(){return Math.random();}function EzlC(QKiOSY) {QKiOSY.open();}functi" ascii
    $s19 = "FhrXBZFAfZvUxuDfhUwEoLS*/yqaYTmztvRafm();var NgFAv = [TSalyoKGmBf[0], TSalyoKGmBf[1]];var rIzY=398-398;while(true) {if(rIzY>NgFA" ascii
    $s20 = " 0x0);}function rtbczfP() {var acUa=100000;var iYsuRM = 100;return sjRYzco()*(acUa-iYsuRM)+iYsuRM;}function DiTqgbFi(hmVoj) {var" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}