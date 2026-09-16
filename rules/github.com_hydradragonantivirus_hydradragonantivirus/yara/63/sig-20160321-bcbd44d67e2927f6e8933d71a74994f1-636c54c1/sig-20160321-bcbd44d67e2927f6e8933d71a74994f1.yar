rule sig_20160321_bcbd44d67e2927f6e8933d71a74994f1 {
  meta:
    description = "datamaliciousorder - file 20160321_bcbd44d67e2927f6e8933d71a74994f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5899459b91ae0754256c50305894a6399cbbd4e22e927bd0d7b5105320667dd"

  strings:
    $s1  = "var gV = \"2\";var J = \"\\x3816\";var RN = \"218\\x33\\x36\";function ZWvDt(C3){return C3;};var YS = \"df\";var kWE = \"s\";var" ascii
    $s2  = "(){return hTgQ;}()) + (function SX(){return V;}()) + (function D(){return K;}()) + Q0 + ZrnNZ]();WScript[(function kP(){return e" ascii
    $s3  = "ec\";var WRg = \"\\x61\\x74e\\x4f\";var q0 = \"\\x43re\";var Wy = function ideAd() {return WScript[q0 + WRg + FCGWk(ahAk) + LrJ]" ascii
    $s4  = "rn Wmqi;}()) + F(hTgQ) + p0(V) + (function GZHFE(){return K;}()) + (function fHg(){return Q0;}()) + ZrnNZ]();WScript[enokb + Pam" ascii
    $s5  = "; N = sx(); o0 = WScript[HpTUl(q0) + VcsU(WRg) + ahAk + zd(LrJ)](N); var q = true; while (q){try {o0[(function ExI(){return xt;}" ascii
    $s6  = ";};function QCYc(TkJ, ltnkA){return TkJ - ltnkA;};function YxgXu(){return gzxSo(q0) + WRg + PBU(ahAk) + oQQ(LrJ);};function tfcR" ascii
    $s7  = "1; OfF++){if (lB() != 0){dhYGG = true;o = true;break;}}function WCm() {return dhYGG && o;};if (WCm()){iTr = Wy[RCdBd + (function" ascii
    $s8  = " 4 ) {WScript[enokb + iap(Jx) + eg](tfcR() * 10)};q = false;} catch(e){};}GqvN = WScript[YxgXu()](NInKK(DjF) + (function YBu(){r" ascii
    $s9  = "Wy[O + RaHpb(d)](coT, 0, 0);};function sx(){return eBEga + KAv(iAXdM) + (function qenwQ(){return HF;}()) + kE(oETFo) + uON(rbvk)" ascii
    $s10 = "()) + Abaq(Ik) + ZOSfi]((function WM(){return nfn;}()) + wjj, kUFL(SwPx) + (function Trx(){return KR;}()) + w(PS) + (function cN" ascii
    $s11 = ") + IJ]();Q(iTr);tnO = \"\" + (function sws(){return HO;}()) + (function C2(){return D0;}()) + uRD(APZNK) + (function otJwg(){re" ascii
    $s12 = "(){return 22;};function lB(){var Ndjx = new this[(function u(){return Rj;}()) + rgwe(wfx)]();var llg = Ndjx[Wmqi + (function muH" ascii
    $s13 = "(){return HbPEY;}()) + (function Nd(){return VxrVm;}()) + oR + (function GdyjY(){return rNLK;}()) + AvT + QbGv + b(QZv) + JFdt +" ascii
    $s14 = "nokb;}()) + Jx + Kz(eg)](tfcR());var Ndjx = new this[m(Rj) + (function v(){return wfx;}())]();var YqUx = Ndjx[(function y(){retu" ascii
    $s15 = "rn BwCJZ;}()) + XkCWh(yQi)] = 0;GqvN[(function Obpnr(){return wcGzc;}()) + ay(ThmN) + yLHeS(bvN)](iTr, 2 );GqvN[pW(lc) + YVRK(kh" ascii
    $s16 = "eturn X1;}()) + DVKTO(C0) + lw(ezQ));GqvN[(Vjg(xt) + (function vCC(){return Ik;}()) + (function c(){return ZOSfi;}()))]();GqvN[l" ascii
    $s17 = "rn L;}()) + G2 + zbVj(Oot) + ggT(c0) + TUbe + hu(RzNR) + F1(Uqg) + NZ + dhYGG ? ZWvDt(YB) + (function ODr(){return kWE;}()) + (f" ascii
    $s18 = ")) + pm(YrkJ)](nsx(UXxbt) + C(inq) + qM(msOk)) + YAF + AA + (function GvsS(){return DBP;}()) + (function EZn(){return NQevc;}())" ascii
    $s19 = " (function eAv(){return Mtjly;}()) + haBbt, false);o0[(function Qq(){return OxL;}()) + (function E0(){return Ytfj;}())]();while " ascii
    $s20 = "xJ = \"AjRm\";TSixJ = QCYc(LjxJG, YqUx);return QCYc(tnO, TSixJ);}var dhYGG = false;var o = false;for (var OfF = 0; OfF < tfcR() " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}