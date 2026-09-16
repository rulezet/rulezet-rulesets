rule sig_20160323_8d0c0b8e2eb5f8ebfd592ce20408e7ae {
  meta:
    description = "datamaliciousorder - file 20160323_8d0c0b8e2eb5f8ebfd592ce20408e7ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a461827295b0bfe9ac3417e3b30e1db20aa659d59a0e90cf13e02479883dda"

  strings:
    $s1  = "(k1) + JCV(da) + Y0(lX)]();WScript[Mrp(f0) + DG(cz)](F());var bin = new this[PeI(FWr)](),d = bin[D(JL) + IQx(d0) + zmM + k1 + da" ascii
    $s2  = " + EK(lX)]();WScript[r(f0) + CMe(cz)](F());var bin = new this[s(FWr)](),v = bin[GY(JL) + gG(d0) + bHn(zmM) + ZNd(k1) + nCl(da) +" ascii
    $s3  = "function aN(ST){var _112crap = \"s\"; return \"\" + ST + \"\";};function d2(dKz){var _112crap = \"s\"; return \"\" + dKz + \"\";" ascii
    $s4  = "n \"\" + x + \"\";};function zY(mR){var _112crap = \"s\"; return \"\" + mR + \"\";};var fq = \"kHb%o\",Hx = \"%\\x2f\";var p0 = " ascii
    $s5  = "+ aRq(XF) + oIY + O0(tR);}; oJD = xx(); rYx = WScript[VCL + T0(OoJ) + y(k) + J(TIm)](oJD); var C = true; while (C){try {rYx[qa(I" ascii
    $s6  = " K = false,I = function B() {return WScript[VCL + Rl(OoJ) + k + GqH(TIm)](bdI(viK) + i + hP(b0) + cB(o));}();function Fs(ENH){I[" ascii
    $s7  = "K){function F(){return 22;};var Tl = 0,c = 0;function g(){var bin = new this[SM(FWr)](),NQN = bin[Ze(JL) + mQ(d0) + KRJ(zmM) + a" ascii
    $s8  = "e (rYx[pY(Cbf) + Fn(ljd) + j1(lT) + TAt] < 4 ) {WScript[f0 + qw(cz)](F() * 10)};C = false;} catch(Ld){C = (rt + Jqg(Gqx), ik + i" ascii
    $s9  = "\\x65O\";var i0 = \"r\",Tms = IWh[\"ch\"+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](1);function cm(l){var _112crap = \"s\"; " ascii
    $s10 = "\\x53he\\x6c\";var i = \"\\x69p\\x74.\",viK = \"W\\x53cr\";function Rl(yL){var _112crap = \"s\"; return \"\" + yL + \"\";};funct" ascii
    $s11 = "var Oi = \"\\x61\",i2 = \"daf\";var Zs = \"af\";function iB(Hq){var _112crap = \"s\"; return \"\" + Hq + \"\";};function Mkp(Vo)" ascii
    $s12 = "function o0(So){var _112crap = \"s\"; return \"\" + So + \"\";};function xVf(hzM){var _112crap = \"s\"; return \"\" + hzM + \"\"" ascii
    $s13 = " \"s\"; return \"\" + j0 + \"\";};function aRq(lP){var _112crap = \"s\"; return \"\" + lP + \"\";};function O0(Xo){var _112crap " ascii
    $s14 = "_112crap = \"s\"; return \"\" + wE + \"\";};function q(Pst){var _112crap = \"s\"; return \"\" + Pst + \"\";};function uH(DF){var" ascii
    $s15 = " jE + \"\";};function PeI(dx){var _112crap = \"s\"; return \"\" + dx + \"\";};function s(Y){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = "65\",YOD = \"\\x65n\";var pdg = \"o\\x70\";function k3(O3){var _112crap = \"s\"; return \"\" + O3 + \"\";};function VUP(K2){var " ascii
    $s17 = ") * 1; hy++){if (g() != 0){wB = true; c = \"07t9gasdf76ags\" + 123313 * Tl + c; qQ = true; c = \"07t9gasdf76ags\" + 123313 * Tl " ascii
    $s18 = "nction oIR(hFK){var _112crap = \"s\"; return \"\" + hFK + \"\";};function Ux(If){var _112crap = \"s\"; return \"\" + If + \"\";}" ascii
    $s19 = "turn \"\" + s0 + \"\";};function r(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};function CMe(y0){var _112crap = \"s\"; re" ascii
    $s20 = "\" + H + \"\";};function N(gO){var _112crap = \"s\"; return \"\" + gO + \"\";};function C0(LK){var _112crap = \"s\"; return \"\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}