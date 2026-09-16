rule sig_20160323_18795469b9bba640f0f319a9c4ff3e4b {
  meta:
    description = "datamaliciousorder - file 20160323_18795469b9bba640f0f319a9c4ff3e4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1bcc0da9596ab03ce0f44fa0f5a51358004cdf607c46e524de73ad467b24109"

  strings:
    $s1  = "function H2(hdl){var _112crap = \"s\"; return \"\" + hdl + \"\";};var mjy = \"cyG1\",X2 = \"l\\x6fs\\x65\";var TGA = mjy[\"ch\"+" ascii
    $s2  = "eJ = function H() {return WScript[sx(U) + sp(FU) + MB(Sy) + Nae(Nwa)](p0 + J + VO(W) + HcD);}();function tCK(T){qeJ[Ed(So)](T, 0" ascii
    $s3  = "r _112crap = \"s\"; return \"\" + jo + \"\";};function TQ(Tap){var _112crap = \"s\"; return \"\" + Tap + \"\";};var As = \"Jbu:" ascii
    $s4  = ", 0);};function hg(){return uw(ce) + ip(z) + uF + jf + Wgi(HY) + tVh(DK) + AiA(WM);};function Pe(D, zP){return D - zP;};function" ascii
    $s5  = "= \"X\";var uF = \"\\x2e\",z = \"\\x58ML2\";var ce = \"MS\";function Ed(A){var _112crap = \"s\"; return \"\" + A + \"\";};var So" ascii
    $s6  = "(sb == Gk) && (sb == true)) ? true : false;};if (sb && JY() && Gk){function iG() {return qeJ[h(w) + Fgv + h0(v) + CsG(po) + R(r0" ascii
    $s7  = "WScript[Y0](Q());var S = new this[IKb](),Eu = S[i(JKP) + c(Cqm) + hUZ(sX) + qc(gZe) + V(cAN) + E0(ulu)]();WScript[Qul(Y0)](Q());" ascii
    $s8  = "hile (xV[z1(pTC) + prb(r4) + Rv(Opk)] < 4 ) {WScript[qPf(Y0)](Q() * 10)};vC = false;} catch(cIq){vC = (K0(W1) + rwp, Ze(G1) + DJ" ascii
    $s9  = "){var _112crap = \"s\"; return \"\" + wJ + \"\";};var X1 = \"am\",TP = \"S\\x74\\x72e\";var JG = \"\\x4fDB.\",TX = \"AD\";functi" ascii
    $s10 = "r _112crap = \"s\"; return \"\" + oru + \"\";};function R(D0){var _112crap = \"s\"; return \"\" + D0 + \"\";};function F0(nSU){v" ascii
    $s11 = " return \"\" + wWZ + \"\";};function AKr(lo){var _112crap = \"s\"; return \"\" + lo + \"\";};function R0(bjV){var _112crap = \"s" ascii
    $s12 = "; return \"\" + U0 + \"\";};function u(zo){var _112crap = \"s\"; return \"\" + zo + \"\";};function s(aXh){var _112crap = \"s\";" ascii
    $s13 = "tion prb(k2){var _112crap = \"s\"; return \"\" + k2 + \"\";};function Rv(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};var" ascii
    $s14 = "\"\" + q + \"\";};function f0(XNx){var _112crap = \"s\"; return \"\" + XNx + \"\";};var Cfa = \"\\x25/\",UU = \"MP\";var j0 = \"" ascii
    $s15 = "return \"\" + nJ + \"\";};function AiA(xC){var _112crap = \"s\"; return \"\" + xC + \"\";};var WM = \"T\\x50\",DK = \"\\x54\";va" ascii
    $s16 = "pt[s(U) + jTh(FU) + Sy + l(Nwa)](naF); var vC = true; while (vC){try {xV[j1(xN) + f1](B0, Y1(hr) + KE(PJG) + n(RS) + Set(rcp) + " ascii
    $s17 = "eturn \"\" + Sfy + \"\";};function Kc(OlP){var _112crap = \"s\"; return \"\" + OlP + \"\";};function IEq(wxo){var _112crap = \"s" ascii
    $s18 = "2\"+\"At\"](0);function q1(nqW){var _112crap = \"s\"; return \"\" + nqW + \"\";};var Px = \"Fi\\x6c\\x65\",u0 = \"\\x65T\\x6f\";" ascii
    $s19 = "\" + wxo + \"\";};function za(vy){var _112crap = \"s\"; return \"\" + vy + \"\";};function r2(Vg){var _112crap = \"s\"; return " ascii
    $s20 = "function H2(hdl){var _112crap = \"s\"; return \"\" + hdl + \"\";};var mjy = \"cyG1\",X2 = \"l\\x6fs\\x65\";var TGA = mjy[\"ch\"+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}