rule sig_20160321_29700f855ab478b05c337a7ac4d74d0b {
  meta:
    description = "datamaliciousorder - file 20160321_29700f855ab478b05c337a7ac4d74d0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c0d42c5518b37e9c5a937b3e964f353fcc06d9fa5f43368a76c7768f686921"

  strings:
    $s1  = "function qJmSJ(b0){return b0;};function BcU(l4){return l4;};var bTZMj = \"162\";var HjUT = \"\\x318368\";var ZL = \"2\";function" ascii
    $s2  = "+ (function w(){return zd;}()); jDAi = Gq(); PAfAA = WScript[eFe + Gv(SPcOM) + (function BHFO(){return cdQ;}()) + (function eyjg" ascii
    $s3  = "var SPcOM = \"\\x72\\x65at\";var eFe = \"C\";var JCi = function cHRm() {return WScript[eFe + (function y(){return SPcOM;}()) + c" ascii
    $s4  = "unction iQRdG(){return fTZ;}()) + (function pSj(){return Jy;}())]();WScript[(function jbBs(){return c;}()) + Fu](mODr());var WeX" ascii
    $s5  = "ction kXNTM(){return fTZ;}()) + (function qAN(){return Jy;}())]();WScript[Wmdf(c) + Cbh(Fu)](mODr());var WeXh = new this[aaRD(Ur" ascii
    $s6  = "){return CxX;}()), false);PAfAA[cHNK(OYPcm) + kWuKp(td)]();while (PAfAA[Nl(NYq) + (function Dg(){return rCR;}())] < 4 ) {WScript" ascii
    $s7  = "a(jMd) + (function W(){return iZcG;}()) + wtcQS + lJOJ;};function bQt(QDPcO, cL){return QDPcO - cL;};function SLrr(){return (fun" ascii
    $s8  = "ction G(){return eFe;}()) + SPcOM + K(cdQ) + (function RwM(){return vuMU;}());};function mODr(){return 22;};function tq(){var We" ascii
    $s9  = "n yoy() {return JRueQ && X;};if (yoy()){iUSc = JCi[uc(h0) + (function d(){return MUZzM;}()) + (function kT(){return DmO;}()) + (" ascii
    $s10 = "[c + Fu](mODr() * 10)};Cv = false;} catch(e){};}arvHm = WScript[SLrr()](PS(zc) + CvU(E) + (function I(){return D0;}()) + PVA + F" ascii
    $s11 = "\"il\";var H = \"getM\";function tZv(j0){return j0;};function Ini(mLt){return mLt;};function K1(YbsDN){return YbsDN;};function I" ascii
    $s12 = "lrB;}()) + (function Izg(){return xyO;}())]();Q(iUSc);ttheR = \"\" + (function Cw(){return Dvo;}()) + gd(qaiFV) + xcLA(Pa) + (fu" ascii
    $s13 = ") + f0(u0)]((function e0(){return UIHYZ;}()) + Dvcw) + (function z(){return TYMug;}()) + XZeAC + (function OAHM(){return D;}()) " ascii
    $s14 = "uMU]((function SA(){return XGfGj;}()) + (function Ib(){return i;}()) + kY(xzW) + (function S(){return j;}()) + X0(ZkgCD) + htAdj" ascii
    $s15 = "r JRueQ = false;var X = false;for (var OdnM = 0; OdnM < mODr() * 1; OdnM++){if (tq() != 0){JRueQ = true;X = true;break;}}functio" ascii
    $s16 = " wnOUo(){return UJh;}()) + GYV + cq(jIINL) + (function JPW(){return iSyiP;}())](iUSc, 2 );arvHm[l3(Mi) + (function aLj(){return " ascii
    $s17 = "tion qQmf(){return mI;}()) + (function JkrnI(){return n;}()) + Agd(g0) + TWkh(vtizc) + (function rMryV(){return ba;}()) + IYx(GW" ascii
    $s18 = "(){return vuMU;}())](jDAi); var Cv = true; while (Cv){try {PAfAA[DrkD(ARtd) + qLl(dBD)]((function lMydR(){return pvX;}()), iCKqq" ascii
    $s19 = "(L));}();function Q(Lm){JCi[(function Qy(){return u;}())](Lm, 0, 0);};function Gq(){return (function PSAK(){return tKhfG;}()) + " ascii
    $s20 = "ion x(){return NetWk;}()) + R(Srx) + ADB + (function dq(){return DDoUn;}()) : qJmSJ(ZL) + BcU(HjUT) + (function Xt(){return bTZM" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}