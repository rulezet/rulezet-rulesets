rule sig_20160524_311e6347c300c71bb2e236481a12069d {
  meta:
    description = "datamaliciousorder - file 20160524_311e6347c300c71bb2e236481a12069d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16b0388131b360b6195cfefece7f6e1f12a16ff0cebd8782ed99b861be4a8462"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "(jtprVJ[0]);}();var SWELf=function(){return new ActiveXObject(\"WScript.Shell\");}();var ZXwxKbfXK = jtprVJ[1]+18578+jtprVJ[2];v" ascii
    $s3  = "pc(kCgnMtxx,kibZdbdKpCnW) {kCgnMtxx.Run(kibZdbdKpCnW, 0x1, 0x0);}function lYaQOaw() {var keUO=100000;var iqwZom = 100;return vdg" ascii
    $s4  = "nLSVMQJxHJEZjjChdGcYCTcfpoaFE*/WScript;}function UBBOaRAhF(EXncmY) {var qiNhbpFEHp=[];EXncmY.position=qiNhbpFEHp.length*(8824127" ascii
    $s5  = ";var fScvSRFkd=TJvaV[dRIH];var YBIxHpT=lYaQOaw() + BUBbmC[2];var lJTxfwLx=850-849;var pLRACVIJd = function(){return new ActiveXO" ascii
    $s6  = "dam.charAt(Math.floor(Math.random()*vLxVadam.length));}return zNBqo;}function iNxZDYJxMxfgtz(igMYScAlHXVdzy) {return new ActiveX" ascii
    $s7  = "ath.random();}function sRYE(POLKBi) {POLKBi.open();}function PtAEVWlh(qmEvJHgAm) {qmEvJHgAm.type=1;}function XPaMCcb(tnSh,SvKwv)" ascii
    $s8  = "Knqi()*(keUO-iqwZom)+iqwZom;}function aBHbxuSx(fbbJQ) {var vLxVadam=BUBbmC[13];for(var PGbin=0;PGbin<fbbJQ;PGbin++){zNBqo+=vLxVa" ascii
    $s9  = "Object(igMYScAlHXVdzy);}');var HjFFJdZhczbqSYS=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];TEQhnQJ.Close(" ascii
    $s10 = "FFJdZhczbqSYS[0]+epYhN,0x1,0x0);}tfhWRFPa();function (qlHce) {return new ActiveXObject(qlHce);}" fullword ascii
    $s11 = "r GsWPmhU = function() {return new ActiveXObject(dtRMj(BUBbmC[7],[0,2,4],BUBbmC[8]));}();vqSeG(GsWPmhU,wTbZd.ResponseBody,YBIxHp" ascii
    $s12 = "JOpUBbREKBnhjTpWxi*/IVeetkGcoURjK();var TJvaV = [BUBbmC[0], BUBbmC[1]];var dRIH=945-945;while(true) {if(dRIH>TJvaV.length) break" ascii
    $s13 = ",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function tfhWRFPa() {var TEQhnQJ;var KSQncHfEais=function(){return new " ascii
    $s14 = "mww);UBBOaRAhF(rfVDGQcc);OTTA(rfVDGQcc,vJCtZgNyuN);KRkQmME(rfVDGQcc);}function TKlp(oACZPU,YCOpEjd){KZEZ = BUBbmC[10].split(BUBb" ascii
    $s15 = "ndEnvironmentStrings(BUBbmC[9])}function vqSeG(rfVDGQcc,jCmww,vJCtZgNyuN){rfVDGQcc.open();PtAEVWlh(rfVDGQcc);XPaMCcb(rfVDGQcc,jC" ascii
    $s16 = "}return mxhrnym.substring(3,mxhrnym.length);}function IVeetkGcoURjK() {tQRBnxBRwB().Sleep(5420-983);}function vdgKnqi(){return M" ascii
    $s17 = " {tnSh.write(SvKwv);}function tQRBnxBRwB() {return/*CKSGFxZTWXQRmBOFMbTPjQDAMKQpicfpILteYagMoPpTqwtDpMrwYdHDBnmBJHHxIfOUkXgZzcIp" ascii
    $s18 = "mC[11]);YCOpEjd.open(KZEZ[0]+KZEZ[2]+KZEZ[3], oACZPU, false);YCOpEjd.send();}function dtRMj(xeQRWDBm,HmxhXC,KNIzTOiBb){cltaW=xeQ" ascii
    $s19 = "nction(){return new ActiveXObject(dtRMj(BUBbmC[5],[0,2,4],BUBbmC[6]));}();TKlp(fScvSRFkd,wTbZd);if (wTbZd.status == 100+100) {va" ascii
    $s20 = "T);}if (lJTxfwLx > 0){try {PLEYNZHgpc(pLRACVIJd,YBIxHpT);} catch(e) {}break;};dRIH++;}function VldNrV(uByNmj){return uByNmj.Expa" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}