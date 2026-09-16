rule sig_20160321_354e3f2bffafc15a8dcc71bd49f0a2e9 {
  meta:
    description = "datamaliciousorder - file 20160321_354e3f2bffafc15a8dcc71bd49f0a2e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aec0e9ffddd9835570200e84d80ed8ea335e94124de155101938c4f38fb58476"

  strings:
    $s1  = "var AObDy = \"9hX82LDes\";var tOY = \"ZKA2UxP\";var umhj = tOY[\"c\\x68a\\x72At\"](3);var Xdz = \"\\x316\";var ewXI = \"\\x318" ascii
    $s2  = " WEKl[X + (function wfVPv(){return UH;}()) + TjB + (function Rz(){return Ow;}())]();WScript[kdC(vf)](do0());var WEKl = new this[" ascii
    $s3  = "ion RO(){return TjB;}()) + (function v(){return Ow;}())]();WScript[vf](do0());var WEKl = new this[m0(kxwZf) + kico]();var TUJh =" ascii
    $s4  = " false);IcBO[smxGT + q0]();while (IcBO[rS(m2) + hz + owdW(Oi) + (function wk(){return E;}())] < 4 ) {WScript[C(vf)](do0() * 10)}" ascii
    $s5  = "var SiQS = \"\\x43r\\x65\";var Kbt = function RvpBP() {return WScript[SiQS + Jq(Vpjlm) + ziA(MBi) + SYwu](Wf(zAI) + rMg(HKSN) + " ascii
    $s6  = "n aPLJW - VB;};function krLGs(){return m(SiQS) + G(Vpjlm) + go(MBi) + SYwu;};function do0(){return 22;};function nBhLi(){var WEK" ascii
    $s7  = ") * 1; aRn++){if (nBhLi() != 0){JOH = true;rGB = true;break;}}function c() {return JOH && rGB;};if (c()){yn = Kbt[fOetb(N0) + (f" ascii
    $s8  = "\\x4di\\x6c\\x6ci\";var X = \"get\";function Pmy(GM){return GM;};function m0(Os){return Os;};var kico = \"\\x74\\x65\";var kxwZf" ascii
    $s9  = ";QQtv = false;} catch(e){};}pk = WScript[krLGs()]((function Tpvo(){return yY;}()) + (function CZ(){return lm;}()) + (function wP" ascii
    $s10 = " = 0;pk[sG(E1) + ghvaQ(FJs) + maY(ODLb) + HS + (function K0(){return ieeF;}()) + vMCEh(qpai)](yn, 2 );pk[pfIZg + edjBK]();nEN(yn" ascii
    $s11 = "J(PD) + (function qvMn(){return yhRnm;}()) + b + BYjI(F) + (function O(){return s;}()));}();function nEN(N){Kbt[T0(Y)](N, 0, 0);" ascii
    $s12 = "; var QQtv = true; while (QQtv){try {IcBO[(function BmE(){return YZL;}()) + u(qDcNt)](RhxZ(W0) + pS(rUtre) + (function xUes(){re" ascii
    $s13 = "+ (function y(){return YO;}()) + (function R(){return BCe;}()) + (function N1(){return kaj;}()) + (function m1(){return Oq;}())," ascii
    $s14 = "l = new this[Pmy(kxwZf) + (function NBYXN(){return kico;}())]();var t = WEKl[(function WwuJ(){return X;}()) + ifhyO(UH) + (funct" ascii
    $s15 = "+ bK(Bp) : (function oKw(){return B;}()) + (function xODS(){return ewXI;}()) + Xdz + (function WYU(){return umhj;}());}" fullword ascii
    $s16 = "(){return zSxbE;}()) + ROShs + (function zKcI(){return KCDc;}()) + QU);pk[((function oV(){return YZL;}()) + (function LlSDV(){re" ascii
    $s17 = "};function o(){return EG + EAb(sCT) + z + CvKv(llZ) + iGzs + (function tMZG(){return Bz;}()) + ar;};function zb(aPLJW, VB){retur" ascii
    $s18 = "(function tgs(){return kxwZf;}()) + kico]();var g = WEKl[(function Kmyx(){return X;}()) + U(UH) + TjB + Ow]();var pu = \"ybEpl\"" ascii
    $s19 = "turn q;}()), (function ErzX(){return NdXb;}()) + l + (function dQhT(){return JZzb;}()) + (function oEFn(){return ogy;}()) + WCp " ascii
    $s20 = "ion N2(){return w;}()) + (function L0(){return Kn;}())]);pk[(function J(){return MX;}()) + (function wTK(){return GjTI;}()) + M]" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}