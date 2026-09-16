rule sig_20160324_0dc0dfc02efb80e2230053f8eade928a {
  meta:
    description = "datamaliciousorder - file 20160324_0dc0dfc02efb80e2230053f8eade928a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2886337f7c29063a58a3c14d807218f1cc2e029e696c77492c62228300d0529c"

  strings:
    $s1  = "e,FuG = \"CreateObject\";var l = function Km() {return WScript[FuG](pdd + O0(UiN) + R);}();var Qp = 123213,Fgu = \"MSXML2.XMLHTT" ascii
    $s2  = "Dg](D0 + w(BQ)) + Psf + wpJ + a;}; zX = PX(); y = WScript[FuG](zX); var k = 1; while (k){try {y[QG](vK, hdh + kx(E) + Gh + OJ + " ascii
    $s3  = "SX)](),JlL = Do[XfW + hN + LxS + Wr]();WScript[DS](UI());var Do = new this[r1(NSX)](),dB = Do[XfW + hN + LxS + Wr]();var t = \"U" ascii
    $s4  = "Vq(SP) + v0 + ipz + wlH + QZU + gL, false);y[ULe(W)]();dKO = \"Sleep\";while (y[yLw + xX(H0) + AT] < 4 ) {WScript[dKO](UI() * 10" ascii
    $s5  = "t = 0,S = 0;function lLI(){var Do = new this[NSX](),f = Do[XfW + P(hN) + A(LxS) + Wr]();WScript[DS](UI());var Do = new this[kM(N" ascii
    $s6  = "var SGy = \"c\\x6c\\x6fse\",cbG = \"\\x65\";var Ood = \"\\x6fF\\x69l\",V = \"Sa\\x76e\\x54\";var bt = \"i\\x6fn\",t2 = \"posi\\x" ascii
    $s7  = "var jkb = 2123213,DNK = 0;function gI(BKd){l[l0(L)](BKd, DNK, DNK);};function PX(){return Fgu;};function uC(o, lcr){return o - l" ascii
    $s8  = "tion avX() {return ((D == true) && (D == r0)) ? 1 : DNK;};if (D && avX() && r0){function xIm() {return l[UOF(o1) + b + v + z0 + " ascii
    $s9  = "\" + C + \"\";};var W = \"\\x73end\";function kx(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function Vq(Z0){var _112crap " ascii
    $s10 = "y\",n0 = \"\\x6e\\x73e\\x42\";var UA = \"R\\x65s\\x70\\x6f\";function Uew(e){var _112crap = \"s\"; return \"\" + e + \"\";};var " ascii
    $s11 = "f (lLI() != DNK){D = true; S = \"07t9gasdf76ags\" + 123313 * t + S; r0 = true; S = \"07t9gasdf76ags\" + 123313 * t + S; break;}}" ascii
    $s12 = "mc = \"\\x50\";var B = \"\\x4cHT\\x54\",T = \"2.X\\x4d\";var o0 = \"MS\\x58ML\";function O0(PSJ){var _112crap = \"s\"; return \"" ascii
    $s13 = "ec\";var hN = \"CMi\\x6c\",XfW = \"ge\\x74UT\";function kM(sOd){var _112crap = \"s\"; return \"\" + sOd + \"\";};function r1(peU" ascii
    $s14 = "ar f0 = \"\\x73df\",Xz = \"f\\x61d\\x66a\";function Irt(Z1){var _112crap = \"s\"; return \"\" + Z1 + \"\";};function mcs(EZZ){va" ascii
    $s15 = "p = \"s\"; return \"\" + peU + \"\";};var NSX = \"Da\\x74e\";function l0(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};var" ascii
    $s16 = "112crap = \"s\"; return \"\" + K + \"\";};function A(t1){var _112crap = \"s\"; return \"\" + t1 + \"\";};var Wr = \"o\\x6eds\",L" ascii
    $s17 = "F\";t = uC(JlL, f);var S = \"FAP\";S = uC(dB, JlL);return uC(t, S);}var D = false,r0 = false;for (var O = DNK; O < UI() * 1; O++" ascii
    $s18 = "\"s\"; return \"\" + EZZ + \"\";};var cK = \"\\x61\",ro = \"as\\x64f\";function xX(l1){var _112crap = \"s\"; return \"\" + l1 + " ascii
    $s19 = "/\",D0 = \"\\x25T\\x45M\";function UOF(pfZ){var _112crap = \"s\"; return \"\" + pfZ + \"\";};var Dg = \"\\x72ings\",z0 = \"e\\x6" ascii
    $s20 = "a = \".e\\x78e\",wpJ = \"\\x79U65\";var Psf = \"\\x581\\x73M\";function w(Mw){var _112crap = \"s\"; return \"\" + Mw + \"\";};va" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}