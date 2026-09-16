rule sig_20160524_b022e3eebf3f95d1c3b78ec2ce0ea221 {
  meta:
    description = "datamaliciousorder - file 20160524_b022e3eebf3f95d1c3b78ec2ce0ea221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fab65af6e3dc0436824768fc5e5520bc2e5a242cfc3c7c85770635fdb401a9b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "t(wxESMvfCJALYfQvPDdw[0]);}();var FWKFLYMnTUoN=function(){return new ActiveXObject(\"WScript.Shell\");}();var ViEaOPI = wxESMvfC" ascii
    $s3  = "}function bqQjfqi(IPlXU) {IPlXU.close();}function DhsNvIgEPT(ykItfZAn,nMofHRxbzfaF) {ykItfZAn.Run(nMofHRxbzfaF, 0x1, 0x0);}funct" ascii
    $s4  = "08;while(true) {if(BjFT>fHGSD.length) break;var IDUhgsyJZ=fHGSD[BjFT];var kzumMJG=yLlJOKE() + VbQqTPAFVTmiemGUBdN[2];var qaolkHY" ascii
    $s5  = "var kzumMJG = XXPbrR(tKYtPQchW) + String.fromCharCode(92) + kzumMJG;var LQZFz = function(){return new ActiveXObject(HuWyy(VbQqTP" ascii
    $s6  = "wQUn.length;cIZqxzQX++) {RWYlbhC+=ualuQ[UCwQUn[cIZqxzQX]];}return RWYlbhC.substring(3,RWYlbhC.length);}function ztWZbKlFGyJEV() " ascii
    $s7  = "IWetVoehpMHZBImcRTRUXMUGdetQWoOEMhcAkbIKDPELCNoKrNMlJjusPRmMtdNvILTatifGLluRwlkLLbAVpZO*/WScript;}function kEcZsNLFu(XUIUTU) {va" ascii
    $s8  = "zAFbjSPZb) {zAFbjSPZb.type=1;}function ajTZEyb(DIVp,JRlaR) {DIVp.write(JRlaR);}function zVuXUdFHuW() {return/*eOlsQXeInmlLuosTJg" ascii
    $s9  = "AFVTmiemGUBdN[5],[0,2,4],VbQqTPAFVTmiemGUBdN[6]));}();VJPV(IDUhgsyJZ,LQZFz);if (LQZFz.status == 100+100) {var AKjuNzF = function" ascii
    $s10 = "turn AhZJw;}function evRvvpckXQblJD(zRdGITdFmJiEyf) {return new ActiveXObject(zRdGITdFmJiEyf);}');var pmuZnuSzXwGe=[\"\\x77\\x73" ascii
    $s11 = "function (uzUGJhSvT) {return new ActiveXObject(uzUGJhSvT);}" fullword ascii
    $s12 = ".fromCharCode(92)+ViEaOPI;ZIsdBB = Axrmub.OpenTextFile(VGXfbBHKrBvdy,2,true);ZIsdBB.Write('var VbQqTPAFVTmiemGUBdN=[\"\\x68\\x74" ascii
    $s13 = "B=479-478;var tKYtPQchW = function(){return new ActiveXObject(HuWyy(VbQqTPAFVTmiemGUBdN[3],[0,2,4],VbQqTPAFVTmiemGUBdN[4]));}();" ascii
    $s14 = "9\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function jRhEtKhvSYPyF() {var ZIsdBB;var Axrmub=function(){return ne" ascii
    $s15 = "QqTPAFVTmiemGUBdN[10].split(VbQqTPAFVTmiemGUBdN[11]);RLIVtwr.open(sliQ[0]+sliQ[2]+sliQ[3], OcNbjC, false);RLIVtwr.send();}functi" ascii
    $s16 = "ajTZEyb(hiIpOIod,LKgSL);kEcZsNLFu(hiIpOIod);KRgd(hiIpOIod,HKOZrYwmft);bqQjfqi(hiIpOIod);}function VJPV(OcNbjC,RLIVtwr){sliQ = Vb" ascii
    $s17 = "ion yLlJOKE() {var pBhK=100000;var MiiMSJ = 100;return xpvzBvq()*(pBhK-MiiMSJ)+MiiMSJ;}function ryZCOeZL(cqkIo) {var sytcXgow=Vb" ascii
    $s18 = "M.ExpandEnvironmentStrings(VbQqTPAFVTmiemGUBdN[9])}function bGtrZ(hiIpOIod,LKgSL,HKOZrYwmft){hiIpOIod.open();jvybyUvi(hiIpOIod);" ascii
    $s19 = "() {return new ActiveXObject(HuWyy(VbQqTPAFVTmiemGUBdN[7],[0,2,4],VbQqTPAFVTmiemGUBdN[8]));}();bGtrZ(AKjuNzF,LQZFz.ResponseBody," ascii
    $s20 = "r GYMDxlooGL=[];XUIUTU.position=GYMDxlooGL.length*(3457541-922);}function KRgd(MFtsEwu,jaIGGig) {MFtsEwu.saveToFile(jaIGGig, 2);" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}