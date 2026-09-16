rule sig_20160323_e92252cff3a82eb905459f306425cffd {
  meta:
    description = "datamaliciousorder - file 20160323_e92252cff3a82eb905459f306425cffd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc270b7e5766d16887679cdab1c09e8d4135aedc623f88330dfe8b2c0218a95c"

  strings:
    $s1  = "(Ul)](GVn());var AFx = new this[W + veB(Pz)](),OoL = AFx[JD + VNz + Ew + V0 + Up(Nnm) + r]();WScript[GzJ + TEs(Ul)](GVn());var A" ascii
    $s2  = " l1(LqP) + hgN(zQh);}; R = NVp(); H = WScript[y0 + M(bg) + a(irq) + xJi](R); var q = true; while (q){try {H[WDY(lq)](oS(dQ), o(G" ascii
    $s3  = "function A2(Uk){var _112crap = \"s\"; return \"\" + Uk + \"\";};var Op = \"clos\\x65\";function qAP(C2){var _112crap = \"s\"; re" ascii
    $s4  = "\\x74tp\\x3a\";function oS(ksm){var _112crap = \"s\"; return \"\" + ksm + \"\";};var dQ = \"GET\";function WDY(Z0){var _112crap " ascii
    $s5  = "tion Gh(){var AFx = new this[UbE(W) + Pz](),BQ = AFx[f(JD) + F(VNz) + zm(Ew) + OPd(V0) + E(Nnm) + BZy(r)]();WScript[FHT(GzJ) + P" ascii
    $s6  = "r xJi = \"j\\x65\\x63\\x74\",irq = \"b\";var bg = \"ate\\x4f\",y0 = \"\\x43re\";var fi = false,coQ = function rL() {return WScri" ascii
    $s7  = "rn xjA(X) + aQ + px(jFo) + jO + yzE(y1) + uI + LJ(IPB) + Na;};function oQS(l, S){return l - S;};function Arw(){return y0 + bg + " ascii
    $s8  = "eturn ((ua == mZ) && (ua == true)) ? true : false;};if (ua && OVS() && mZ){function O() {return coQ[CZN + v1(k0) + k1 + B0(Sp) +" ascii
    $s9  = "(zo) + wSS + GWL + NG(PBQ)] < 4 ) {WScript[z(GzJ) + ZHa(Ul)](GVn() * 10)};q = false;} catch(y){q = (i1(oe0) + yY + f2(P1), MA0(j" ascii
    $s10 = "var oe = \"con\",TpN = \"ise\";var FPP = \"l\\x6c\",uI0 = \"CMi\";var Kk = \"getUT\",z0 = \"Da\\x74\\x65\";function FHT(oQa){var" ascii
    $s11 = " _112crap = \"s\"; return \"\" + Tp + \"\";};function nET(K){var _112crap = \"s\"; return \"\" + K + \"\";};function f3(JbP){var" ascii
    $s12 = " \"\";};function f2(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};var xfA = \"KIIass\",P1 = \"\\x64fa\";var yY = \"s\",oe0 =" ascii
    $s13 = "t\"](4);function vS(O1){var _112crap = \"s\"; return \"\" + O1 + \"\";};function pj(De){var _112crap = \"s\"; return \"\" + De +" ascii
    $s14 = "ai) + rD + Nh(MO), A1(vi) + EYq(R1) + kEE + n(td), true);};}function XSr(fw) {var w = (1, 2, 3, 4, 5, fw); return w;};lJ = (ua) " ascii
    $s15 = "u) + L1(yt) + f1 + j0 + am(ST) + htr(i0) + iim(A0) + P0(fn) + Ws(Hz) + lH(C) + To, false);H[Vf(wv) + g]();while (H[eLB(HjB) + Tr" ascii
    $s16 = " + p0 + \"\";};function z(i){var _112crap = \"s\"; return \"\" + i + \"\";};function ZHa(I){var _112crap = \"s\"; return \"\" + " ascii
    $s17 = "g + ys(irq) + xJi](UlL(aD) + V(HA) + BH(YJH) + R0 + fNZ(u));}();function Nrs(aF){coQ[w0 + df(Q)](aF, 0, 0);};function NVp(){retu" ascii
    $s18 = "nction yTP(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};var Th = \"kAEf3Z4\",nsF = \"S\";var LjC = \"IC3tvKj\",vM = \"mJ7" ascii
    $s19 = "};function qtR(An){var _112crap = \"s\"; return \"\" + An + \"\";};var taq = \"/\",gc = \"%\";var lxv = \"EM\\x50\",xa = \"%T\";" ascii
    $s20 = " Ul = \"\\x65p\",GzJ = \"Sl\\x65\";function f(m){var _112crap = \"s\"; return \"\" + m + \"\";};function F(IU){var _112crap = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}