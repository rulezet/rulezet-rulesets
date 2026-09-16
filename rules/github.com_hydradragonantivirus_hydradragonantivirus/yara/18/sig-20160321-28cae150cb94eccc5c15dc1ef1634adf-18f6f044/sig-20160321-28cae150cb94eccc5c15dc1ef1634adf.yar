rule sig_20160321_28cae150cb94eccc5c15dc1ef1634adf {
  meta:
    description = "datamaliciousorder - file 20160321_28cae150cb94eccc5c15dc1ef1634adf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b643ec373d3673087669c17f20a2edeb3c45ed22be9a462e7485e44232063d9"

  strings:
    $s1  = "function el(vD){return vD;};function hXSjv(ZzQwI){return ZzQwI;};function gxJJx(LEPf){return LEPf;};var HbxtC = \"2\";var Y1 = " ascii
    $s2  = "urn epnsN;}()) + (function V(){return iv;}()) + Kzgel(vEKZ)]();WScript[(function hkPO(){return iCo;}()) + b](cU());var o = new t" ascii
    $s3  = "unction yi(){return epnsN;}()) + bo(iv) + (function yEqN(){return vEKZ;}())]();WScript[b0(iCo) + b](cU());var o = new this[(func" ascii
    $s4  = ";break;}}function grlo() {return wwz && gDrXZ;};if (grlo()){qGEp = MMG[kl(nfgN) + GsqD(eXMuz) + (function Zck(){return H0;}()) +" ascii
    $s5  = "N = qLe(); DOBFI = WScript[QWiC + bdcDm(KwBJ) + pvapw + (function cOJg(){return mCAv;}())](DN); var Z = true; while (Z){try {DOB" ascii
    $s6  = "{return WScript[QWiC + (function M(){return KwBJ;}()) + x(pvapw) + (function cn(){return mCAv;}())](DS + C + (function OyE(){ret" ascii
    $s7  = "turn tPc;}()) + jyf + zgL(JN) + sJ(nARzC)] < 4 ) {WScript[iCo + dwsSR(b)](cU() * 10)};Z = false;} catch(e){};}g0 = WScript[ln()]" ascii
    $s8  = "var NjNiB = \"L\\x32\";var n0 = \"\\x58M\";var a = \"MS\";function E(Q){return Q;};var FL = \"nkZg\";var SB = FL[\"charAt\"](0);" ascii
    $s9  = "c = \"8\";var dTfoM = \"Dqz\\x31\";var PD = k[\"charAt\"](2);var i1 = \"w\";var OM = \"B\";var hIBt = iUcm[\"charAt\"](1);functi" ascii
    $s10 = "x52u\";var iXM = \"RGlVk7JJ\";var RWH = iXM[\"charAt\"](2);var n = \"\\x68e\\x6c\";var C = \"i\\x70t.\\x53\";var DS = \"WS\\x63r" ascii
    $s11 = "{return Pdd;};var hMhwl = \"Fq4e.JmGaC\";var ZAbZ = \"\\x50\";var NpsW = \"\\x54\\x54\";var hGJU = \"\\x58MLH\";var Fo = hMhwl[" ascii
    $s12 = "};function wYud(A0){return A0;};var nu = \"mXtETb\";var SoKz = nu[\"charAt\"](0);var ozxEq = \"\\x61\";var agPQj = \"re\";var uG" ascii
    $s13 = "unction WZlG(GxSRr){return GxSRr;};var AsOxl = \"BQKaw\";var BNS = \"SiekRDQV\";var LTIdN = BNS[\"charAt\"](2);var yeS = \"\\x72" ascii
    $s14 = "A[\"charAt\"](1);var sqW = \"\\x63\\x74\";var zME = \"eOb\\x6ae\";var n1 = \"\\x43\\x72\\x65at\";function T(QHe){return QHe;};fu" ascii
    $s15 = "r xW = YsM[\"charAt\"](2);var vwdms = \"open\";var YttGs = \"\\x6aec\\x74\";var FkoB = \"at\\x65O\\x62\";var h0 = \"Cre\";functi" ascii
    $s16 = "unction Kzgel(X0){return X0;};function qOa(vmqdE){return vmqdE;};var BG = \"isQokR\";var vEKZ = BG[\"charAt\"](1);var iv = \"e" ascii
    $s17 = "llo = AsOxl[\"charAt\"](4);var ob = \"t\\x79pe\";var acYW = \"open\";function iwn(FEUJz){return FEUJz;};function CXB(OqJC){retur" ascii
    $s18 = "n pSJg;};function yM(raN){return raN;};var nSiLc = \"7lL3Y\";var qNikK = \"\\x65\";var j = nSiLc[\"charAt\"](1);var cWxeK = \"Fi" ascii
    $s19 = " crsKP[\"charAt\"](2);function gQ(e0){return e0;};function D(N){return N;};var cWAs = \"FhBAUdTA\";var XW = cWAs[\"charAt\"](5);" ascii
    $s20 = "z[\"charAt\"](0);var xDBwR = \"asd\\x6c\";function Jzmh(Q0){return Q0;};var EGVRG = \"ose\";var kpVPg = \"cl\";function ZFSDc(pS" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}