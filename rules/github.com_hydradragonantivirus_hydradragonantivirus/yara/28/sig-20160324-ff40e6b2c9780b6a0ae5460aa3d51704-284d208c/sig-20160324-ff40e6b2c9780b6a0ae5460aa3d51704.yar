rule sig_20160324_ff40e6b2c9780b6a0ae5460aa3d51704 {
  meta:
    description = "datamaliciousorder - file 20160324_ff40e6b2c9780b6a0ae5460aa3d51704.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5a8fa1829b3d0df85d70d760f10410335eae7e34dd967b51b3c754f0a34c97c"

  strings:
    $s1  = "cript[Aw](M());var WB = new this[VXj](),r = WB[U0 + BC + ez + ru]();WScript[e(Aw)](M());var WB = new this[VXj](),Wd = WB[U0 + BC" ascii
    $s2  = " RtW = \"\\x65\\x4fbje\",G = \"Cre\\x61\\x74\";var Ha = false,Ys = \"CreateObject\";var jT = function wm() {return WScript[Ys](N" ascii
    $s3  = "z = (1, 2, 3, 4, 5, U); return rz;};TbK = WScript[aN()](e1(Wpg) + YEc + Xb);JoK = TbK;JoK[(nN)]();JoK[e2(QG)] = y(1);JoK[vZ + fi" ascii
    $s4  = "ion pt() {return jT[gw + KW + glZ + Bw + a(bCG) + iGX](jjQ(gbh) + d) + e0 + fa(UN) + BB;}; JoK = zP(); s = WScript[Ys](JoK); var" ascii
    $s5  = "var WvS = \"c\\x6cose\",G0 = \"\\x65\";var PM = \"ToF\\x69l\",xq = \"Sa\\x76e\";function VlP(A0){var _112crap = \"s\"; return \"" ascii
    $s6  = "df76ags\" + 123313 * j0 + Jkx; break;}}function Ug() {return ((lX == true) && (lX == pV)) ? 1 : hPc;};if (lX && Ug() && pV){func" ascii
    $s7  = "+ hgF + yuN] < 4 ) {WScript[vgS](M() * 10)};XUl = hPc;} catch(H){XUl = (f, Z2(Bf) + g0(Gs), vzz + Lu, 2);};}function y(U) {var r" ascii
    $s8  = "\\x50ry\\x30\";function jjQ(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};var d = \"P\\x25/\",gbh = \"%TE\\x4d\";function " ascii
    $s9  = "\\x74e\";function e(wbw){var _112crap = \"s\"; return \"\" + wbw + \"\";};var Aw = \"Sl\\x65ep\";function v(Unx){var _112crap = " ascii
    $s10 = "ar j = hPc; j < M() * 1; j++){if (WmF() != hPc){lX = true; Jkx = \"07t9gasdf76ags\" + 123313 * j0 + Jkx; pV = true; Jkx = \"07t9" ascii
    $s11 = " + wae(ez) + ru]();var j0 = \"nXH\";j0 = X(r, c);var Jkx = \"Qb\";Jkx = X(Wd, r);return X(j0, Jkx);}var lX = false,pV = false;fo" ascii
    $s12 = "crap = \"s\"; return \"\" + FVW + \"\";};var iGX = \"g\\x73\",bCG = \"tr\\x69\\x6e\";var Bw = \"ent\\x53\",glZ = \"r\\x6fnm\";va" ascii
    $s13 = "var WvS = \"c\\x6cose\",G0 = \"\\x65\";var PM = \"ToF\\x69l\",xq = \"Sa\\x76e\";function VlP(A0){var _112crap = \"s\"; return \"" ascii
    $s14 = " XUl = 1; while (XUl){try {s[nN](TxR, CLK + bzl + ik + rug + Z0 + QC + i + ul + Z1(X0), false);s[Q]();vgS = \"Sleep\";while (s[X" ascii
    $s15 = "(evt){var _112crap = \"s\"; return \"\" + evt + \"\";};function g0(VD){var _112crap = \"s\"; return \"\" + VD + \"\";};var Gs = " ascii
    $s16 = "n \"\" + FS + \"\";};var Xb = \"r\\x65a\\x6d\",YEc = \"\\x42\\x2e\\x53t\";var Wpg = \"\\x41DOD\",Lu = \"\\x61\";var vzz = \"\\x6" ascii
    $s17 = "N = \"\\x6f\\x70\\x65n\";function fa(pO){var _112crap = \"s\"; return \"\" + pO + \"\";};var BB = \"e\\x78e\",UN = \"\\x77H\\x7a" ascii
    $s18 = "on e2(zw){var _112crap = \"s\"; return \"\" + zw + \"\";};var QG = \"ty\\x70e\",XRX = \"o\\x70en\";function e1(FS){var _112crap " ascii
    $s19 = " \"\" + Unx + \"\";};function op(Om){var _112crap = \"s\"; return \"\" + Om + \"\";};function wae(nH){var _112crap = \"s\"; retu" ascii
    $s20 = "f (Ha){function M(){return 22;};var j0 = 0,Jkx = 0;function WmF(){var WB = new this[VXj](),c = WB[U0 + v(BC) + op(ez) + ru]();WS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}