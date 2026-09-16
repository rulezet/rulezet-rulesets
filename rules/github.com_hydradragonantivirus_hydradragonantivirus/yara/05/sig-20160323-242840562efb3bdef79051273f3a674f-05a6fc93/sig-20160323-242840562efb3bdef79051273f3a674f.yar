rule sig_20160323_242840562efb3bdef79051273f3a674f {
  meta:
    description = "datamaliciousorder - file 20160323_242840562efb3bdef79051273f3a674f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade3face35518efe966abd56fceb12080fbe88c35559f17c0a3509c287777922"

  strings:
    $s1  = "this[dbG(iQR)](),iz = e[uBB(MSY) + lS(R0) + Z(Lz) + zLp + aLy(j0) + XY(njV) + VV(Mb)]();WScript[az(Djw)](dSc());var e = new this" ascii
    $s2  = "function L1(Y0){var _112crap = \"s\"; return \"\" + Y0 + \"\";};var Ie = \"s\\x65\",Am = \"\\x63lo\";function VA(dFe){var _112cr" ascii
    $s3  = "pRG) {var oR = (1, 2, 3, 4, 5, pRG); return oR;};c0 = (cDw) ? 14134 : 414234;Y = WScript[IY()](Ej + fGj(uC) + q0(bjO) + qa(UX) +" ascii
    $s4  = "dJ + PK(zz) + HSY + tP(D) + pH(tqt) + Pq, false);X[kt(V3) + G1(kT)]();while (X[os(b) + YWD(uHJ) + B0 + joC(kfh)] < 4 ) {WScript[" ascii
    $s5  = ";var ZAu = \"\\x43\",h0 = false;var m = function oSy() {return WScript[YX(ZAu) + YS(Dm) + TRN(pwF) + H + mPS](db(apb) + Kl(WW) +" ascii
    $s6  = "= \"DoG8fplTgw0\";var Mq = k0[\"ch\"+\"\\x61\"+\"rAt\"](5),zg = \"S\\x6cee\";function os(hPF){var _112crap = \"s\"; return \"\" " ascii
    $s7  = "crap = \"s\"; return \"\" + jKR + \"\";};var A0 = \"Md9b3mLd\",c1 = \"ap9\";var jse = \"SaOff\",Pq = jse[\"ch\"+\"\\x61\"+\"rAt" ascii
    $s8  = "ar Ljn = \"9rQsFD6hM\",z0 = \"ate\";var h4 = Ljn[\"ch\"+\"\\x61\"+\"rAt\"](5);function az(Jhn){var _112crap = \"s\"; return \"\"" ascii
    $s9  = "\" + q1 + \"\";};var Cn = \"kwwO\",KZ = \"te\";var Ukt = \"\\x72i\",LIf = Cn[\"ch\"+\"\\x61\"+\"rAt\"](2);function G2(sFM){var _" ascii
    $s10 = "nction PCo(cUD){var _112crap = \"s\"; return \"\" + cUD + \"\";};var WyH = \"67aP\",LPa = WyH[\"ch\"+\"\\x61\"+\"rAt\"](2);var k" ascii
    $s11 = " \"s\"; return \"\" + AB + \"\";};var RS = \"qom11xwdeK\",Rtd = \"C5x9K\";var JD = \"e\",plf = Rtd[\"ch\"+\"\\x61\"+\"rAt\"](2);" ascii
    $s12 = "N0 + w(Qwa);};function TB(sgp, v){return sgp - v;};function IY(){return N(ZAu) + pct(Dm) + US(pwF) + dEH(H) + Zt(mPS);};/*@cc_on" ascii
    $s13 = "2\",Ho = \"\\x4d\\x53\";function sO(Va){var _112crap = \"s\"; return \"\" + Va + \"\";};var X0 = \"Run\";function db(C){var _112" ascii
    $s14 = "74e\",B0 = \"\\x73ta\";var uHJ = \"\\x79\",b = \"read\";function kt(K3){var _112crap = \"s\"; return \"\" + K3 + \"\";};function" ascii
    $s15 = "sdf76ags\" + 123313 * c0 + f; vu = true; f = \"07t9gasdf76ags\" + 123313 * c0 + f; break;}}function EqU() {return ((cDw == vu) &" ascii
    $s16 = "cDw == true)) ? true : false;};if (cDw && EqU() && vu){function Dmc() {return m[o0(wN) + o + YkJ(tY) + WBI + g(xTG) + Fo(ILs) + " ascii
    $s17 = "= \"y\";var byR = \"od\",VB = \"seB\";var XG = \"s\\x70on\",GK = \"e\";var tbv = a1[\"ch\"+\"\\x61\"+\"rAt\"](2);function cWP(Ze" ascii
    $s18 = "ee\",Qb = RS[\"ch\"+\"\\x61\"+\"rAt\"](5);var mj = \"J\\x59j\",l0 = \"\\x55\\x57B\";var m0 = \"ny\\x41G\";function pbg(zD){var _" ascii
    $s19 = " UMr + \"\";};var tg = \"oF\\x69l\\x65\",LW = \"v\\x65T\";var Se = \"\\x53a\";function Hx(MF){var _112crap = \"s\"; return \"\" " ascii
    $s20 = "74\";function dbG(nKW){var _112crap = \"s\"; return \"\" + nKW + \"\";};function eAs(h2){var _112crap = \"s\"; return \"\" + h2 " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}