rule sig_20160324_5e6645419ded4cdb8c8ac616ecd2708c {
  meta:
    description = "datamaliciousorder - file 20160324_5e6645419ded4cdb8c8ac616ecd2708c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6cb1f7b681110660118c8ef19431d4ce92bdc98415ca1784ab9bc5ed65c7944"

  strings:
    $s1  = "ect\";var xnR = function WUN() {return WScript[x](tXE(Y) + k0 + BR);}();var htD = 123213,S = \"MSXML2.XMLHTTP\";var ynR = 212321" ascii
    $s2  = "function CKC(W1){var _112crap = \"s\"; return \"\" + W1 + \"\";};var vu = \"clo\\x73e\";function b(KP){var _112crap = \"s\"; ret" ascii
    $s3  = "{var C = new this[hXZ](),t = C[jcL(Fic) + O2 + SP + o0]();WScript[eGO + xtf](zym());var C = new this[WN(hXZ)](),yL = C[Fic + pK(" ascii
    $s4  = "O2) + SP + l(o0)]();WScript[eGO + CHO(xtf)](zym());var C = new this[hXZ](),O0 = C[Fic + O2 + SP + o0]();var lu = \"tbK\";lu = u(" ascii
    $s5  = "tyT) + Q) + OYz + V(XDp) + AEt + p;}; Bpe = Yrd(); xd = WScript[x](Bpe); var Do = 1; while (Do){try {xd[FH(iS)](R, Gwl + Ec + Vg" ascii
    $s6  = " = (JhS(zc) + xT, wXb + i0, Jqd + TWq, 2);};}function oXG(g) {var FY = (1, 2, 3, 4, 5, g); return FY;};O1 = WScript[Dd()](WB + Z" ascii
    $s7  = " = 0;function k(BgO){xnR[d(k1)](BgO, W, W);};function Yrd(){return S;};function u(H, pEU){return H - pEU;};function Dd(){return " ascii
    $s8  = "rn ((n == true) && (n == t0)) ? 1 : W;};if (n && IEK() && t0){function oyN() {return xnR[ojh + Loj + TRv + D(x1) + d0 + kc](LGr(" ascii
    $s9  = "(KV) + RHS + WV + nSd, false);xd[W0]();o = \"Sleep\";while (xd[gXb + z + pYR] < 4 ) {WScript[o](zym() * 10)};Do = W;} catch(oQ){" ascii
    $s10 = "\"\";};var o0 = \"o\\x6eds\",SP = \"is\\x65c\";var O2 = \"C\\x4dil\\x6c\",Fic = \"get\\x55\\x54\";function WN(nVr){var _112crap " ascii
    $s11 = "function G(MU){var _112crap = \"s\"; return \"\" + MU + \"\";};var ZIv = \"\\x65\",xo = \"\\x77\\x72it\";var Dsx = \"typ\\x65\"," ascii
    $s12 = "turn \"\" + urx + \"\";};var p = \"\\x78\\x65\",AEt = \"Pn\\x2ee\";var XDp = \"\\x45\\x43\\x57\\x44n\",OYz = \"\\x63\\x4b\\x41" ascii
    $s13 = "ar gFA = \"\\x4cHT\\x54\",Ym = \"\\x4c2.XM\";var r = \"\\x4d\\x53XM\";function tXE(pS){var _112crap = \"s\"; return \"\" + pS + " ascii
    $s14 = "J){var _112crap = \"s\"; return \"\" + J + \"\";};var Q = \"%\\x2f\",tyT = \"\\x25TEM\\x50\";function D(vm){var _112crap = \"s\"" ascii
    $s15 = "p = \"s\"; return \"\" + f0 + \"\";};var tC = \"\\x74\\x69\\x6fn\",WT = \"po\\x73i\";var jv = \"o\\x64y\",WEI = \"on\\x73e\\x42" ascii
    $s16 = "\";function JhS(Ye){var _112crap = \"s\"; return \"\" + Ye + \"\";};var xT = \"\\x61\",zc = \"asd\\x66\";var pYR = \"t\\x65\",z " ascii
    $s17 = " \"G\\x45T\";function FH(J0){var _112crap = \"s\"; return \"\" + J0 + \"\";};var iS = \"\\x6fpe\\x6e\";function V(urx){var _112c" ascii
    $s18 = "rn \"\" + g1 + \"\";};function pK(nS){var _112crap = \"s\"; return \"\" + nS + \"\";};function l(BM){var _112crap = \"s\"; retur" ascii
    $s19 = " + nVr + \"\";};var hXZ = \"Da\\x74\\x65\";function d(nG){var _112crap = \"s\"; return \"\" + nG + \"\";};var k1 = \"R\\x75\\x6e" ascii
    $s20 = "n CHO(mBd){var _112crap = \"s\"; return \"\" + mBd + \"\";};var xtf = \"\\x70\",eGO = \"S\\x6cee\";function jcL(g1){var _112crap" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}