rule sig_20160321_95f200fb5aa47393174ad737dc4c4d73 {
  meta:
    description = "datamaliciousorder - file 20160321_95f200fb5aa47393174ad737dc4c4d73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9893e067c8a607ff0c7444d5b925fdee61c75bdc48c4f8c9951709a4bcb6373c"

  strings:
    $s1  = "function OtI(q0){return q0;};function MTAj(pSF){return pSF;};var EHnKP = \"s3qto2v3KTe\";var d0 = EHnKP[\"ch\\x61rAt\"](5);var Q" ascii
    $s2  = "eturn WScript[mPyG + I(K) + (function LJlaK(){return IH;}())](JBq(dD) + (function NPTE(){return t;}()) + Uuz(tsi) + (function yY" ascii
    $s3  = "V;}()) + C0(UbUBp) + Wo(DcMs); wK = q(); pVNny = WScript[VN(mPyG) + K + IH](wK); var qq = true; while (qq){try {pVNny[kQpS(esN) " ascii
    $s4  = "ction v(){return Z0;}()) + lJ(f) + GEKX(nNqdr) + rZC]();WScript[(function FLzts(){return G;}()) + (function iY(){return qMBWG;}(" ascii
    $s5  = "nction pML(){return nNqdr;}()) + Tmn(rZC)]();WScript[KSsLw(G) + RoOLd(qMBWG)](sIB());var rfm = new this[jfBD]();var P = rfm[(fun" ascii
    $s6  = " (pVNny[(function cgwN(){return cJ;}()) + T(XyXQD) + (function JN(){return Wa;}()) + qlH(IA) + Mjg] < 4 ) {WScript[G + somnu(qMB" ascii
    $s7  = "return sPsdi;};var wL = \"zKey\";var WtMMF = \"y\";var RnHLj = \"o\\x64\";var Tw = \"B\";var KYLRK = wL[\"ch\\x61rAt\"](2);var R" ascii
    $s8  = " + Cbh + p;};function fT(sOPQT, uu){return sOPQT - uu;};function z(){return (function OCh(){return mPyG;}()) + oNgwN(K) + (funct" ascii
    $s9  = "r (var kqjcV = 0; kqjcV < sIB() * 1; kqjcV++){if (aZAD() != 0){w = true;En = true;break;}}function acH() {return w && En;};if (a" ascii
    $s10 = "WG)](sIB() * 10)};qq = false;} catch(e){};}eFsY = WScript[z()](OSc(eqMk) + (function RFXJu(){return UPCY;}()) + (function YU(){r" ascii
    $s11 = "rn Uv;};function somnu(FsMQH){return FsMQH;};var LE = \"Y93EXp0JGAj\";var qMBWG = LE[\"ch\\x61rAt\"](5);var G = \"S\\x6ce\\x65\"" ascii
    $s12 = "lUl = \"l\";var rgLYh = \"oFi\";var kTXEM = PNli[\"ch\\x61rAt\"](5);var Rvw = \"S\\x61\\x76e\";function F1(hHg){return hHg;};fun" ascii
    $s13 = "M\";var RV = \"1BeneR\";var jRH = RV[\"ch\\x61rAt\"](2);var gbym = \"Da\\x74\";function KSsLw(qJLj){return qJLj;};function RoOLd" ascii
    $s14 = "function OtI(q0){return q0;};function MTAj(pSF){return pSF;};var EHnKP = \"s3qto2v3KTe\";var d0 = EHnKP[\"ch\\x61rAt\"](5);var Q" ascii
    $s15 = "UuH){return RTUuH;};function VTi(HeySX){return HeySX;};var o0 = \"E3NMhuC\";var U = \"i\\x73df\";var l2 = o0[\"ch\\x61rAt\"](4);" ascii
    $s16 = "x65\";var IA = Rq[\"ch\\x61rAt\"](5);var Wa = \"dyst\";var XyXQD = hM[\"ch\\x61rAt\"](2);var cJ = \"re\";function hRWck(qRUyM){r" ascii
    $s17 = "72ay.\";var h = \"ky\";var bkEJv = qSso[\"ch\\x61rAt\"](3);var aTv = \"://\";var CEi = \"\\x68t\\x74p\";var l0 = \"\\x47ET\";fun" ascii
    $s18 = ";var rg = \"C\\x72ea\";function Rwn(LzCh){return LzCh;};var rseA = \"bNJTMSGd\";var p = \"P\";var Cbh = rseA[\"ch\\x61rAt\"](3);" ascii
    $s19 = " = \"lR\";var O = \"un\";var Vfvu = I0[\"ch\\x61rAt\"](1);function JBq(QcXTb){return QcXTb;};function Uuz(cX){return cX;};var CJ" ascii
    $s20 = "+ jpS]((function YvmLK(){return l0;}()), (function wBkxo(){return CEi;}()) + (function rHY(){return aTv;}()) + bkEJv + Y(h) + yN" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}