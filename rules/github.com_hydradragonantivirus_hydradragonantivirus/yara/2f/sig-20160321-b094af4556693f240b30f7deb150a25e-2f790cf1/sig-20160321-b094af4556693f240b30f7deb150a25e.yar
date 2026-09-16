rule sig_20160321_b094af4556693f240b30f7deb150a25e {
  meta:
    description = "datamaliciousorder - file 20160321_b094af4556693f240b30f7deb150a25e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b05e5f325822740fc28bf8cd9bd527088d2df4f820fcbafd12a710bace575a7"

  strings:
    $s1  = "var YEJN = \"\\x38162\";var sxYOn = \"6\";var YGV = \"2\\x31\\x383\";var lEVl = \"Chkdj0lGs\";var TCEDr = \"1UIDfQg8ZH\";var pCd" ascii
    $s2  = "\\x41\\x74\"](5);var C = \"ec\";var SlHT = \"teObj\";var KeE = \"\\x43\\x72e\\x61\";var ius = function f() {return WScript[tLxPh" ascii
    $s3  = "ah;}()) + xlsP(j); l = IYB(); a = WScript[f0(KeE) + (function ex(){return SlHT;}()) + (function JJ(){return C;}()) + cEjor(XKrI)" ascii
    $s4  = ")]();WScript[(function MQY(){return jcqjR;}()) + W(f1)](QdeBJ());var wP = new this[Z(lHGh) + (function HF(){return lakbc;}())]()" ascii
    $s5  = "s0(jHziE)]();while (a[Wd(pKHF) + VV(voIy) + (function UzRb(){return vQGMk;}())] < 4 ) {WScript[MoW(jcqjR) + (function XEeNL(){re" ascii
    $s6  = "+ Tdhi(QKeHD) + WWuv]();WScript[YU(jcqjR) + OYFv(f1)](QdeBJ());var wP = new this[X0(lHGh) + (function tBGg(){return lakbc;}())](" ascii
    $s7  = "YJFI(H, lQlp){return H - lQlp;};function RfF(){return KeE + mg(SlHT) + Mciof(C) + (function JYU(){return XKrI;}());};function Qd" ascii
    $s8  = "turn f1;}())](QdeBJ() * 10)};HGJ = false;} catch(e){};}F = WScript[RfF()]((function L(){return wQ;}()) + KK(je) + (function h1()" ascii
    $s9  = "ar vfJ = IK[\"ch\\x61r\\x41\\x74\"](2);var st = \"GET\";function r(fWUg){return fWUg;};var t = \"open\";var sa = \"\\x65c\\x74\"" ascii
    $s10 = ");var Ln = wP[(function uFfi(){return JLVC;}()) + (function vYEaP(){return qQEw;}()) + (function Oy(){return QKeHD;}()) + x(WWuv" ascii
    $s11 = "SBE(){return FhMyV;}()) + (function N0(){return aMRg;}()) : (function Al(){return YGV;}()) + (function Uu(){return sxYOn;}()) + " ascii
    $s12 = "](l); var HGJ = true; while (HGJ){try {a[(function ZKC(){return t;}())]((function XAlXA(){return st;}()), TwFvf(vfJ) + Q0 + ZgRo" ascii
    $s13 = "q + (function Iv(){return lbcSz;}()) + (function yRsgh(){return ae;}()) + (function KvEg(){return k;}()) + Y0(Dl) + Ir + y(C1) +" ascii
    $s14 = "eBJ(){return 22;};function kZ(){var wP = new this[(function TAFS(){return lHGh;}()) + QTK(lakbc)]();var Ur = wP[JLVC + Jh(qQEw) " ascii
    $s15 = "var fcJz = \"XJ\";fcJz = YJFI(nj, Ln);return YJFI(Y, fcJz);}var ceVK = false;var fdAB = false;for (var Nv = 0; Nv < QdeBJ() * 1;" ascii
    $s16 = "ction U(){return SlHT;}()) + (function rmEa(){return C;}()) + (function urYq(){return XKrI;}())](jrYP + (function mWJlX(){return" ascii
    $s17 = ")) + (function pYG(){return YWo;}()) + cd + rZH + (function qrb(){return YE;}()) + HDnh](DY(KsNcX) + (function YxR(){return h;}(" ascii
    $s18 = " (function emw(){return nhlx;}()) + (function iY(){return ZyxjA;}()) + (function hj(){return h0;}()) + kLvoq(fX), false);a[U1 + " ascii
    $s19 = "return zyK;}()) + (function ViM(){return FLsO;}()) + q(qO) + (function dX(){return bMLsP;}()) + (function pMhls(){return IZnh;}(" ascii
    $s20 = ";var nj = wP[JLVC + (function KwaL(){return qQEw;}()) + QKeHD + (function A(){return WWuv;}())]();var Y = \"vn\";Y = YJFI(Ln, Ur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}