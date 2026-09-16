rule sig_20160323_1ad14b6357d36d4ee10a1d69a9c24554 {
  meta:
    description = "datamaliciousorder - file 20160323_1ad14b6357d36d4ee10a1d69a9c24554.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14729153761e4b7e3ee95c96f896db94255ebcdfc459b08fe4a10c00d4c8387e"

  strings:
    $s1  = "T[MJ + SNi(Uvl) + XtK(RXD) + il(YE)]();WScript[Fq(f) + qi(VF) + DPP(VKS)](qH());var T = new this[WdG(OqV) + hLJ](),I = T[MJ + s1" ascii
    $s2  = "};var Gn = \"\\x6ae\\x63t\",GQM = \"\\x4fb\";var w = \"eate\",Q = \"\\x43r\";var s = false,x = function S() {return WScript[IM(Q" ascii
    $s3  = "(Uvl) + RXD + OED(YE)]();WScript[Lmy(f) + up0(VF) + VKS](qH());var T = new this[RX(OqV) + T0(hLJ)](),fvT = T[Uhj(MJ) + Gw(Uvl) +" ascii
    $s4  = "function lAS(y4){var _112crap = \"s\"; return \"\" + y4 + \"\";};var gPz = \"s\\x65\",dff = \"clo\";function vi(m2){var _112crap" ascii
    $s5  = "ZN(m) + w0 + eRT + r1;}; pwg = UtR(); up = WScript[Qr(Q) + p(w) + FQ(GQM) + SY(Gn)](pwg); var C = true; while (C){try {up[y2](p1" ascii
    $s6  = "eturn \"\" + cgi + \"\";};var YE = \"co\\x6e\\x64s\",RXD = \"\\x6c\\x6cis\\x65\";var Uvl = \"\\x54\\x43\\x4di\",MJ = \"getU\";fu" ascii
    $s7  = "nction g(mUm, zS){return mUm - zS;};function Rs(){return s0(Q) + mGh(w) + A(GQM) + CEG(Gn);};/*@cc_on  @if (@_win32 || @_win64) " ascii
    $s8  = "76ags\" + 123313 * W + Jbn; break;}}function dJv() {return ((dB == VbL) && (dB == true)) ? true : false;};if (dB && dJv() && VbL" ascii
    $s9  = "\"\";};var uE = \"Run\",rd = \"ell\";var aT = \"pt.Sh\",rIQ = \"WS\\x63\\x72i\";function IM(HO){var _112crap = \"s\"; return \"" ascii
    $s10 = "+ P0(HL) + C1] < 4 ) {WScript[hzu(f) + W0(VF) + gXO(VKS)](qH() * 10)};C = false;} catch(ASe){C = (dO(x1) + RJ(ayy), df(O0) + gv(" ascii
    $s11 = "\\x45U\",m = \"\\x33O9Pr\";function C0(KaT){var _112crap = \"s\"; return \"\" + KaT + \"\";};function t0(cE){var _112crap = \"s" ascii
    $s12 = "s\"; return \"\" + zny + \"\";};function i(tds){var _112crap = \"s\"; return \"\" + tds + \"\";};var JM = \"a\\x66a\",k0 = \"\\x" ascii
    $s13 = "3);var w1 = \"C\\x72eat\";function AZN(t1){var _112crap = \"s\"; return \"\" + t1 + \"\";};var r1 = \"\\x78e\",eRT = \"x\\x4a\\x" ascii
    $s14 = "+\"\\x72\"+\"At\"](3);var QW = \"LHT\\x54\",hHY = \"2.XM\";var QE = \"\\x4d\\x53X\\x4d\\x4c\";function t(q){var _112crap = \"s\"" ascii
    $s15 = "f(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};function gv(Lc){var _112crap = \"s\"; return \"\" + Lc + \"\";};function Y" ascii
    $s16 = "on il(v){var _112crap = \"s\"; return \"\" + v + \"\";};function s1(BaO){var _112crap = \"s\"; return \"\" + BaO + \"\";};functi" ascii
    $s17 = "var _112crap = \"s\"; return \"\" + r + \"\";};function A(SK){var _112crap = \"s\"; return \"\" + SK + \"\";};function CEG(js){v" ascii
    $s18 = "\"\";};var vWK = \"GE\\x54\";function Cs(G0){var _112crap = \"s\"; return \"\" + G0 + \"\";};var y2 = \"op\\x65n\",L1 = \"0f7e80" ascii
    $s19 = "function SNi(UJc){var _112crap = \"s\"; return \"\" + UJc + \"\";};function XtK(sco){var _112crap = \"s\"; return \"\" + sco + " ascii
    $s20 = "_112crap = \"s\"; return \"\" + zUY + \"\";};function L2(vZR){var _112crap = \"s\"; return \"\" + vZR + \"\";};function xP(CiI){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}