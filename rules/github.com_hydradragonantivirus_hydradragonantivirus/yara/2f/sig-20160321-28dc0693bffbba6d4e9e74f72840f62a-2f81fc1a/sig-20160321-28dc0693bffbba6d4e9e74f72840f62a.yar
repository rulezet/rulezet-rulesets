rule sig_20160321_28dc0693bffbba6d4e9e74f72840f62a {
  meta:
    description = "datamaliciousorder - file 20160321_28dc0693bffbba6d4e9e74f72840f62a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "474a4ced2834ae6a2d5e56096c6089b209f61dbbd586f749c037f86c0b56bb90"

  strings:
    $s1  = "function vmE(Ts){return Ts;};var inR = \"8yOe\";var q = \"\\x3162\";var jXtp = inR[\"char\\x41\\x74\"](0);var EqwD = \"21836\";f" ascii
    $s2  = ") + kMtg + Fa(O0) + FA(yVf) + (function Tlm(){return yEXK;}()); PWSZr = THCqa(); XjHKZ = WScript[b + bpXe + (function pgkUy(){re" ascii
    $s3  = "{return f0;}()) + wtdSh + iQKhg + NPkVL(PZ)]();WScript[Mv(hBILL) + itf](uo());var ZWNgf = new this[d0 + (function tiY(){return h" ascii
    $s4  = "h) + Di(iQKhg) + (function syirj(){return PZ;}())]();WScript[BPR(hBILL) + EXoj(itf)](uo());var ZWNgf = new this[(function Zokn()" ascii
    $s5  = " a;}());};function hwcmi(DQk, U){return DQk - U;};function Uzu(){return (function J(){return b;}()) + VYM(bpXe) + nj(hpsob) + VS" ascii
    $s6  = "ak;}}function MjoAD() {return l && LZIq;};if (MjoAD()){S = yPdkW[BOai + (function swV(){return cSd;}()) + (function e0(){return " ascii
    $s7  = "ction qai(){return unfl;}())] < 4 ) {WScript[hBILL + itf](uo() * 10)};IwK = false;} catch(e){};}QfIcm = WScript[Uzu()]((function" ascii
    $s8  = "so\";var f1 = \"-man\";var dfcc = \"iss\";var GVjro = \"\\x61n\";var evm = \"\\x2f\\x2f\";var w0 = \"\\x74tp:\";var ZCVl = \"\\x" ascii
    $s9  = "\"\\x6ae\\x63\";var hpsob = \"at\\x65O\\x62\";var bpXe = \"re\";var b = h[\"char\\x41\\x74\"](3);var yPdkW = function gUZya() {r" ascii
    $s10 = "Odp){return Odp;};function hlF(qDLL){return qDLL;};var cSWk = \"\\x64\\x66\";var yPOK = \"fas\";var JthR = \"as\\x64\";function " ascii
    $s11 = "pEf;}()) + LFG(s) + dvY(Y) + JAihp + NQbH(isf) + tq](SBX(h1) + Nwizr + BezX + hMuQI(Zz)) + (function AW(){return wLd;}()) + Z(eF" ascii
    $s12 = "MvAa;}()) + (function dHx(){return hZEFk;}())]();var r = ZWNgf[(function e(){return G;}()) + DfjV(KNGn) + XzYu + j(f0) + We(wtdS" ascii
    $s13 = "{return d0;}()) + L(hMvAa) + M(hZEFk)]();var VrZ = ZWNgf[(function DCE(){return G;}()) + (function Ccpt(){return KNGn;}()) + XzY" ascii
    $s14 = "turn hpsob;}()) + T(OhOS) + aNjjR(WmY)](PWSZr); var IwK = true; while (IwK){try {XjHKZ[(function jR(){return hGdxJ;}())]((functi" ascii
    $s15 = " DO(){return rzhB;}()) + l ? (function uCsf(){return JthR;}()) + Qj(yPOK) + hlF(cSWk) : vmE(EqwD) + (function Re(){return jXtp;}" ascii
    $s16 = "u + Cq(f0) + (function Yrc(){return wtdSh;}()) + iQKhg + h0(PZ)]();var u = \"dq\";u = hwcmi(r, pTYy);var R = \"hL\";R = hwcmi(Vr" ascii
    $s17 = "b + (function JXAMA(){return bpXe;}()) + hpsob + srFf(OhOS) + (function F(){return WmY;}())]((function OO(){return AAoz;}()) + d" ascii
    $s18 = "(VQY) + vLxnZ + (function HVfeg(){return XOuJZ;}()) + HK(f));}();function QjJ(iuDgt){yPdkW[(function EF(){return onpcw;}())](iuD" ascii
    $s19 = " jCw;}()) + (function ZjFU(){return H0;}()) + sxQ(hZx) + Q0(OxS) + WLSdi(yjGSD) + (function Dopyh(){return rzeN;}()) + (function" ascii
    $s20 = " zoH(){return A;}()) + EnYSo(iUgK) + V(O1) + nuW + Y0);QfIcm[(o(hGdxJ))]();QfIcm[bCyaZ(qrM)] = 1;QfIcm[H(WOGmv) + EGrxw + (funct" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}