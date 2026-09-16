rule sig_20160524_0d5e244d088faa00624d2c8608e6825d {
  meta:
    description = "datamaliciousorder - file 20160524_0d5e244d088faa00624d2c8608e6825d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31e1382c9b0fd9866980fa8992b9e8555b26a3f0304e32f1aed0067cdd5426c"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "(){return new ActiveXObject(rCVcJPMf[0]);}();var HNSIb=function(){return new ActiveXObject(\"WScript.Shell\");}();var EMgleqS = " ascii
    $s3  = " {mdXfyCGA.Run(ptnxROKUHzoo, 0x1, 0x0);}function oACZPUY() {var COpE=100000;var jdKZEZ = 100;return CTcfpoa()*(COpE-jdKZEZ)+jdKZ" ascii
    $s4  = "HXVd*/WScript;}function YFFdfZfhO(yyKAhV) {var BlGhbuYuaa=[];yyKAhV.position=BlGhbuYuaa.length*(3863424-613);}function PtQB(jpqW" ascii
    $s5  = "EZ;}function DobvTbkI(etqEi) {var SfCEFOsq=fntsomqlnvagxWkBZU[13];for(var kdtRM=0;kdtRM<etqEi;kdtRM++){jxeQR+=SfCEFOsq.charAt(Ma" ascii
    $s6  = "r taWmxhr=oACZPUY() + fntsomqlnvagxWkBZU[2];var nymYFVvd=768-767;var gKnqisRYE = function(){return new ActiveXObject(wtDpM(fntso" ascii
    $s7  = "73\\x62\\x6d\\x7a\\x6b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function RhuXsxmFeZXNWj() {var cORVPBXzJcuja;va" ascii
    $s8  = "omqlnvagxWkBZU[0], fntsomqlnvagxWkBZU[1]];var rxTK=948-948;while(true) {if(rxTK>NTKlp.length) break;var oGPxsmncl=NTKlp[rxTK];va" ascii
    $s9  = "PjQD[3], ZTWXQR, false);mBOFMbT.send();}function wtDpM(rwYdHDBn,mBJHHx,IfOUkXgZz){QJxHJ=rwYdHDBn.split(IfOUkXgZz);EZjjChd = fnts" ascii
    $s10 = "MUQ,ICukLkz) {jpqWMUQ.saveToFile(ICukLkz, 2);}function PCPvwfX(TyVLf) {TyVLf.close();}function MTKQFAbmUN(mdXfyCGA,ptnxROKUHzoo)" ascii
    $s11 = "SgOjHuNEJBRyaIZXoexx[0]+zumIf,0x1,0x0);}RhuXsxmFeZXNWj();function (KOOJYcO) {return new ActiveXObject(KOOJYcO);}" fullword ascii
    $s12 = "hq = function(){return new ActiveXObject(wtDpM(fntsomqlnvagxWkBZU[5],[0,2,4],fntsomqlnvagxWkBZU[6]));}();SGFx(oGPxsmncl,VWlhq);i" ascii
    $s13 = "ZdbdKp);}function SGFx(ZTWXQR,mBOFMbT){PjQD = fntsomqlnvagxWkBZU[10].split(fntsomqlnvagxWkBZU[11]);mBOFMbT.open(PjQD[0]+PjQD[2]+" ascii
    $s14 = "th.floor(Math.random()*SfCEFOsq.length));}return jxeQR;}function bKFKfMzacfkVkm(THugdWamVYRBYz) {return new ActiveXObject(THugdW" ascii
    $s15 = "f (VWlhq.status == 100+100) {var mEvJHgA = function() {return new ActiveXObject(wtDpM(fntsomqlnvagxWkBZU[7],[0,2,4],fntsomqlnvag" ascii
    $s16 = "omqlnvagxWkBZU[12];for(cIpnLSVM=0;cIpnLSVM<mBJHHx.length;cIpnLSVM++) {EZjjChd+=QJxHJ[mBJHHx[cIpnLSVM]];}return EZjjChd.substring" ascii
    $s17 = "= PDUDxcJ.OpenTextFile(zumIf,2,true);cORVPBXzJcuja.Write('var fntsomqlnvagxWkBZU=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x7" ascii
    $s18 = "IV(eetkGc) {eetkGc.open();}function oURjKuPK(yMgrYrToa) {yMgrYrToa.type=1;}function kIoXNFC(HbmP,vwLmf) {HbmP.write(vwLmf);}func" ascii
    $s19 = "(3,EZjjChd.length);}function zyJUSJbBLjIpD() {RKSGZhNsmc().Sleep(3582-376);}function CTcfpoa(){return Math.random();}function FE" ascii
    $s20 = "ak;};rxTK++;}function PLEYNZ(EIkwcA){return EIkwcA.ExpandEnvironmentStrings(fntsomqlnvagxWkBZU[9])}function Mtxxk(ibZdbdKp,CnWtQ" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}