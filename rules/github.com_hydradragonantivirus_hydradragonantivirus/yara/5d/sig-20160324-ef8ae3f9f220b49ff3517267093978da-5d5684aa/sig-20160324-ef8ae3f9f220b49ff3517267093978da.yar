rule sig_20160324_ef8ae3f9f220b49ff3517267093978da {
  meta:
    description = "datamaliciousorder - file 20160324_ef8ae3f9f220b49ff3517267093978da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "655a8d38efcf2f6a6f3289fe7232a61bfd0ca40204f1b8d53cf221d6da729b31"

  strings:
    $s1  = "var Ez = \"eU7\",u = Ez[\"\"+\"\\x63\"+\"h\"+\"\\x61\"+\"r\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](0);var HXU = \"c\\x6cos\";function c" ascii
    $s2  = "(U)]();WScript[WLI](pDW());var Hkw = new this[m0](),Ndy = Hkw[dRL + QK + IF + U]();WScript[WLI](pDW());var Hkw = new this[m0]()," ascii
    $s3  = "s0(T0), 2);};}function ZQ(q) {var RJ = (1, 2, 3, 4, 5, q); return RJ;};GS0 = WScript[d()](dw + Te + M);atF = GS0;atF[(R)]();atF[" ascii
    $s4  = "); o = WScript[tz](atF); var cv = 1; while (cv){try {o[R](wVz(rJ), p1 + l + L0 + s + OMs + eX + HK + U1 + NjV, false);o[dZ]();iK" ascii
    $s5  = "FA() && b){function Uq() {return O[L(Ji) + Y + n(LuS) + HFn + QX + h0(a0)](K0 + FW) + WRd + YsW(sCn) + p0(pHA) + Ae;}; atF = EV(" ascii
    $s6  = "h(vM) + m + KI);}();var xm = 123213,vk = \"MSXML2.XMLHTTP\";var axt = 2123213,zA = 0;function T(eq){O[y](eq, zA, zA);};function " ascii
    $s7  = "e; mxw = \"07t9gasdf76ags\" + 123313 * GS + mxw; break;}}function AFA() {return ((rW == true) && (rW == b)) ? 1 : zA;};if (rW &&" ascii
    $s8  = " = \"ec\\x74\";var bj = \"\\x65O\\x62j\",rx = \"Crea\\x74\";var X = false,tz = \"CreateObject\";var O = function WO() {return WS" ascii
    $s9  = "o = \"Sleep\";while (o[r0(Ro) + W + r] < 4 ) {WScript[iKo](pDW() * 10)};cv = zA;} catch(fd){cv = (fHR + zk(U2), y0 + x0(Y0), OV " ascii
    $s10 = "\\x61\\x74e\";var WLI = \"\\x53l\\x65ep\";function oy(zuU){var _112crap = \"s\"; return \"\" + zuU + \"\";};function ok(p){var _" ascii
    $s11 = " return \"\" + x + \"\";};var m0 = \"Dat\\x65\",y = \"R\\x75\\x6e\";var cWZ = \"T\\x50\",f = \"MLH\\x54\";var wK = \"L\\x32\\x2e" ascii
    $s12 = "d@*/if (X){function pDW(){return 22;};var GS = 0,mxw = 0;function PQZ(){var Hkw = new this[EqN(m0)](),j = Hkw[dRL + QK + IF + oy" ascii
    $s13 = "r Zr = \"\\x69on\",Y1 = \"\\x70o\\x73it\";function o0(j1){var _112crap = \"s\"; return \"\" + j1 + \"\";};var eA = \"o\\x64y\",j" ascii
    $s14 = "wO = Hkw[dRL + QK + ok(IF) + U]();var GS = \"h\";GS = v(Ndy, j);var mxw = \"w\";mxw = v(wO, Ndy);return v(GS, mxw);}var rW = fal" ascii
    $s15 = " = false;for (var lH = zA; lH < pDW() * 1; lH++){if (PQZ() != zA){rW = true; mxw = \"07t9gasdf76ags\" + 123313 * GS + mxw; b = t" ascii
    $s16 = "; return \"\" + p + \"\";};var U = \"\\x63onds\",IF = \"ll\\x69se\";var QK = \"TCM\\x69\",dRL = \"\\x67etU\";function EqN(x){var" ascii
    $s17 = "112crap = \"s\"; return \"\" + Q + \"\";};var r = \"\\x65\",W = \"st\\x61t\";var Ro = \"rea\\x64y\",kl = \"\\x70\";var Qu = \"Sl" ascii
    $s18 = "return \"\" + ghr + \"\";};var DZa = \"\\x6fF\\x69le\",OwY = \"\\x53\\x61veT\";function qJs(Q0){var _112crap = \"s\"; return \"" ascii
    $s19 = "\";var SBY = \"Re\\x73\\x70\";function xG(rY){var _112crap = \"s\"; return \"\" + rY + \"\";};var lJF = \"\\x65\",G = \"wri\\x74" ascii
    $s20 = "58M\";function Sgh(xpo){var _112crap = \"s\"; return \"\" + xpo + \"\";};var KI = \"\\x68ell\",m = \"\\x70\\x74\\x2eS\";var vM =" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}