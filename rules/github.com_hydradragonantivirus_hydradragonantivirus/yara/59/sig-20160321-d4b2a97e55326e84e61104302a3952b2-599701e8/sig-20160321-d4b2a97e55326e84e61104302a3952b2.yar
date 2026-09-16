rule sig_20160321_d4b2a97e55326e84e61104302a3952b2 {
  meta:
    description = "datamaliciousorder - file 20160321_d4b2a97e55326e84e61104302a3952b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28bc3af6781370d28cb8b4790ba3191894081c3708768e57f885cf5dc4efce3e"

  strings:
    $s1  = "tion Bwubr(){return f;}()) + nPpEB(b) + xGVw; xJfKd = KNbzr(); NZYP = WScript[p + ATdWq + (function rc(){return tDmAG;}()) + XoA" ascii
    $s2  = "function oLodw(o0){return o0;};var QzQv = \"62\";var ziJDa = \"\\x383\\x368\\x31\";var yGNY = \"2\\x31\";function dbG(yqvSJ){ret" ascii
    $s3  = "rn RH;}()) + POFW + m(SfaTI) + (function PdybS(){return nxA;}())]();WScript[SH(D) + HT + ILaB(vCFX)](Hu());var wkTy = new this[u" ascii
    $s4  = "POFW + SfaTI + (function HLfJ(){return nxA;}())]();WScript[j0(D) + aRP(HT) + rh(vCFX)](Hu());var wkTy = new this[cRh(piUqo) + gI" ascii
    $s5  = " WScript[HyM(p) + (function ayq(){return ATdWq;}()) + tDmAG + (function xgSJI(){return MW;}())](rvpcC(bTt) + (function rCkEU(){r" ascii
    $s6  = "{return WMT + shk(rSyLh) + yP(gRI) + gOP + (function q(){return ysVf;}());};function SMIEe(FREfP, j){return FREfP - j;};function" ascii
    $s7  = " ou && o;};if (qfi()){LmBPC = KizI[jvhSx(O1) + hvOtx(Dpj) + qYAnV + Fs(yJr) + WFoeW + (function i(){return PNUv;}()) + XPz + JQP" ascii
    $s8  = "MPE;}())] < 4 ) {WScript[D + zXhI(HT) + Ycy(vCFX)](Hu() * 10)};xkeqK = false;} catch(e){};}OOKQ = WScript[G()](Yfqc + l + MhPxM(" ascii
    $s9  = "eturn LtR;}()) + Jay(vXdW) + (function eJvO(){return LcOq;}()));}();function v(Irn){KizI[JC(yHAN)](Irn, 0, 0);};function KNbzr()" ascii
    $s10 = "xpv + m0(hZ)](LmBPC, 2 );OOKQ[(function i0(){return Jab;}()) + (function g0(){return GW;}())]();v(LmBPC);XBEpk = \"\" + (functio" ascii
    $s11 = "tion SEI(){var wkTy = new this[piUqo + gAMGM]();var Qi = wkTy[gFCqr + (function eRI(){return c;}()) + jB + (function TwJK(){retu" ascii
    $s12 = "unction JRBf(){return il;}()) + (function KiK(){return VkDWy;}()) + (function nl(){return MKB;}()) + HRylU + GAHL(qFvFv) + (func" ascii
    $s13 = "P]((function tOlP(){return Ns;}()) + L(uVqaM) + mJgjh(F0) + (function w(){return AgpEx;}()) + (function V(){return yS;}())) + (f" ascii
    $s14 = "nction iDEJ(){return xxTbE;}()) + taqCz + ou ? dbG(Kn) + Ck(UmnkA) + xkt(xwYO) : oLodw(yGNY) + (function AESD(){return ziJDa;}()" ascii
    $s15 = "{return CNU;}()) + (function aeun(){return Zn;}())] = 1;OOKQ[DUs + rij](NZYP[(function ktP(){return b1;}()) + Ki(xg) + (function" ascii
    $s16 = "ZYP[Cz(B) + (function Rk(){return dq;}())]();while (NZYP[(function xgrGw(){return YrGpO;}()) + mV(qDes) + (function mi(){return " ascii
    $s17 = " G(){return p + zlt(ATdWq) + (function arkq(){return tDmAG;}()) + (function zk(){return MW;}());};function Hu(){return 22;};func" ascii
    $s18 = "Z(MW)](xJfKd); var xkeqK = true; while (xkeqK){try {NZYP[sej](jAzR, udqSb(qMynE) + lVDKL(gkc) + (function gz(){return Lt;}()) + " ascii
    $s19 = "= false;var o = false;for (var rss = 0; rss < Hu() * 1; rss++){if (SEI() != 0){ou = true;o = true;break;}}function qfi() {return" ascii
    $s20 = "xbEI(){return UGg;}()) + bzbNa(CLlp) + (function Lkk(){return L0;}()) + xr(v1) + bA0 + zv(AHgmO) + qL + KtBj(c0) + NB(nbz) + (fu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}