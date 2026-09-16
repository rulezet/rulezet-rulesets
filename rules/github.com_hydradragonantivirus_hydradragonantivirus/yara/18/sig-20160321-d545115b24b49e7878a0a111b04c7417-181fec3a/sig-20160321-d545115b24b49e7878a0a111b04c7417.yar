rule sig_20160321_d545115b24b49e7878a0a111b04c7417 {
  meta:
    description = "datamaliciousorder - file 20160321_d545115b24b49e7878a0a111b04c7417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98448534732d332043cf51b6870532b15325e3fc6a7efee9c57c09a2f03e950d"

  strings:
    $s1  = "function LR(ApXcP){return ApXcP;};var x2 = \"6\\x32\";var UmMHy = \"\\x38368\\x31\";var rvL = \"21\";function KxzYA(jUeR){return" ascii
    $s2  = "();var UuDw = rGNCR[(function bfUu(){return yQX;}()) + I(x) + r + jpK + (function ck(){return Jvu;}())]();WScript[G0 + Wmxax(PV)" ascii
    $s3  = "ion XPkYr(){return aW;}())]();while (MGz[ZVD(Arb) + mD(YHUM) + (function C(){return CeR;}()) + SENH] < 4 ) {WScript[(function Hk" ascii
    $s4  = " qD = YfQd[\"char\\x41t\"](1);var F = \"Cr\\x65at\";var OTXzp = function W() {return WScript[(function BJNS(){return F;}()) + Qq" ascii
    $s5  = " uv + F0(YsIE) + Gz(uLCo) + nn(q) + OoslT + jowvf(eUltT) + IxD; zIH = bBppQ(); MGz = WScript[(function a0(){return F;}()) + cpLO" ascii
    $s6  = "};function vluB(L, A){return L - A;};function KyukS(){return (function iqqmh(){return F;}()) + NJ(qD) + aOz(h) + (function XvINc" ascii
    $s7  = "urn oqZ && vLqu;};if (XG()){EMsi = OTXzp[O1(Wlw) + (function GFv(){return gM;}()) + krOdz(Xfke) + (function JRefW(){return Cwah;" ascii
    $s8  = ") + v1(k)](MGz[(function Dj(){return IcOM;}()) + (function JK(){return TleLn;}()) + Hy(sv) + (function sTfF(){return dH;}())]);W" ascii
    $s9  = "R(){return G0;}()) + (function nPAc(){return PV;}())](GVMDE() * 10)};y = false;} catch(e){};}W0 = WScript[KyukS()](gdsAx(q0) + q" ascii
    $s10 = "wx = \"t\\x70\\x3a\";var oE = \"ht\";var biZb = \"GET\";function fMGZ(Kevt){return Kevt;};var ZSj = \"en\";var FY = \"op\";var k" ascii
    $s11 = "ript[MffHO(G0) + (function WCFra(){return PV;}())](GVMDE());var rGNCR = new this[QqqWQ(ddz)]();var qlB = rGNCR[tPbj(yQX) + c(x) " ascii
    $s12 = "}()) + (function L2(){return vZb;}()) + nnu(xs) + lG(pVBc) + XJjw + ZHy(VJ) + hQRl](lYRdN(lFd) + (function hb(){return v;}())) +" ascii
    $s13 = "on TRuf(){return fXjq;}())](EMsi, 2 );W0[dD + (function F1(){return AahXM;}()) + (function GBf(){return GdFTM;}())]();uCGm(EMsi)" ascii
    $s14 = "FY;}()) + ZSj]((function aKHBJ(){return biZb;}()), sGJM(oE) + (function Do(){return poPwx;}()) + (function Yspr(){return Vs;}())" ascii
    $s15 = "alse;var vLqu = false;for (var Qy = 0; Qy < GVMDE() * 1; Qy++){if (RiZ() != 0){oqZ = true;vLqu = true;break;}}function XG() {ret" ascii
    $s16 = "R) + (function X0(){return rsB;}()) + (function bNr(){return OVPx;}()) + h0(dR) + My + BEi(SpPD), false);MGz[ehTct(Jyv) + (funct" ascii
    $s17 = "koVo) + mWQvB(SC) + (function jamw(){return vygFy;}()) : LR(rvL) + UmMHy + (function wLcW(){return x2;}());}" fullword ascii
    $s18 = "+ r + V(jpK) + Jvu]();var QbA = \"CVbr\";QbA = vluB(fQoz, UuDw);var E = \"DPt\";E = vluB(qlB, fQoz);return vluB(QbA, E);}var oqZ" ascii
    $s19 = ";QbA = \"\" + (function gZl(){return c0;}()) + S0(qwBfL) + Va(P) + TWqga + (function C1(){return s;}()) + (function aLe(){return" ascii
    $s20 = "CC(yNfM) + C0 + O2 + (function ejbI(){return i;}()));W0[(FY + fMGZ(ZSj))]();W0[(function uX(){return njM;}())] = 1;W0[PzFk(YBGpd" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}