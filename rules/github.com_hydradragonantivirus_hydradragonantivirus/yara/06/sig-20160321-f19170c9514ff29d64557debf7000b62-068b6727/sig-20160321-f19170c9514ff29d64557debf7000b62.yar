rule sig_20160321_f19170c9514ff29d64557debf7000b62 {
  meta:
    description = "datamaliciousorder - file 20160321_f19170c9514ff29d64557debf7000b62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9aad23183c1ba58b7a880f202828be0c3305ca9aa1f14647b1719fa65780be2c"

  strings:
    $s1  = "function bX(vXW){return vXW;};var TjPrX = \"\\x368162\";var mCE = \"2\\x3183\";function WZ(VL){return VL;};var d1 = \"eVQdA\";va" ascii
    $s2  = " KYr = WScript[qz(UK) + (function o0(){return aNioE;}()) + tSXa + Llz + (function bc(){return IYkk;}())](r); var SeNy = true; wh" ascii
    $s3  = "u(AJn) + Wnm]();WScript[CejS(fMm) + YhI](q());var lrT = new this[CZW(Ahl)]();var OeKpm = lrT[(function vs(){return ua;}()) + n(i" ascii
    $s4  = "x65Ob\";var aNioE = \"ea\";var UK = \"Cr\";var dNPVF = function HC() {return WScript[UK + (function AaCPw(){return aNioE;}()) + " ascii
    $s5  = "n ua;}()) + (function Uygv(){return i;}()) + (function v(){return JZ;}()) + (function O(){return AJn;}()) + Wnm]();WScript[fMm +" ascii
    $s6  = "ion nkLb(o, IV){return o - IV;};function E(){return ChsXw(UK) + a(aNioE) + zLy(tSXa) + Llz + (function iOD(){return IYkk;}());};" ascii
    $s7  = "E = 0; vE < q() * 1; vE++){if (mAVRr() != 0){z = true;jRGm = true;break;}}function l() {return z && jRGm;};if (l()){c = dNPVF[(f" ascii
    $s8  = " ) {WScript[boGa(fMm) + (function e(){return YhI;}())](q() * 10)};SeNy = false;} catch(e){};}lHSSv = WScript[E()]((function OrT(" ascii
    $s9  = "};function u(Fn){return Fn;};function n(f){return f;};var Wnm = \"nds\";var AJn = \"co\";var JZ = \"ise\";var i = \"ll\";var ua " ascii
    $s10 = "= \"jfp3\";var p0 = BCRWo[\"charAt\"](1);var wCsG = d1[\"charAt\"](3);var Adyw = \"dfas\";var pai = \"as\";function ewIw(MOT){re" ascii
    $s11 = " zrVn = \"veTo\";var GiFB = \"\\x61\";var x = A[\"charAt\"](4);function WVl(BkZh){return BkZh;};function ylJW(uFEy){return uFEy;" ascii
    $s12 = "n YCore;};function k(VyQb){return VyQb;};var PU = \"60QEMG\";var iAbmP = \"MP%/\";var yrO = PU[\"charAt\"](3);var H0 = \"%T\";fu" ascii
    $s13 = " mqaq = Jsh[\"charAt\"](4);var QoH = \"\\x47ET\";function tdrl(xFt){return xFt;};var WoJA = \"\\x6fp\\x65n\";var t0 = \"ect\";va" ascii
    $s14 = "1 = \"Ug4n1OI\";var m = z1[\"charAt\"](3);var XQaq = \"\\x74i\\x6f\";var Qe = \"\\x70\\x6f\\x73i\";function zru(vfZB){return vfZ" ascii
    $s15 = " kY(){return zrVn;}()) + Cl(C)](c, 2 );lHSSv[RXIq + (function RO(){return dlHVP;}())]();qJO(c);xQcGJ = \"\" + u0 + mqa + (functi" ascii
    $s16 = "ction jvqbX(){return toO;}())]();while (KYr[(function G(){return KaDx;}()) + O0(Uq) + (function Z0(){return qI;}()) + Pxnwb] < 4" ascii
    $s17 = "turn cy;}()) + (function zQAE(){return qVaD;}()) + (function lbVb(){return rqo;}()) + (function z0(){return FASn;}()); r = nX();" ascii
    $s18 = ";}()) + zaId + cf(Q) + z ? WZ(pai) + (function HHU(){return Adyw;}()) + (function qslGJ(){return wCsG;}()) + (function z2(){retu" ascii
    $s19 = "(function UFUd(){return q0;}()) + (function a0(){return WJK;}()) + AnMx(shk), false);KYr[(function RXr(){return yzSI;}()) + (fun" ascii
    $s20 = "0;}()) + yv(nhbR) + XEzGy(H) + cJz](H0 + iZc(yrO) + k(iAbmP)) + wetKV(kUq) + (function t(){return kRI;}()) + (function zxau(){re" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}