rule sig_20160324_2f3477581127f5ec7bc81c85d824afbd {
  meta:
    description = "datamaliciousorder - file 20160324_2f3477581127f5ec7bc81c85d824afbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6836ebe5cfef80a5a17e34d857737b695298fb03a911eaa983618afaadee95a"

  strings:
    $s1  = " {return WScript[TQ](z + T + Qyc);}();var YAW = 123213,YVY = \"MSXML2.XMLHTTP\";var pFV = 2123213,sIY = 0;function QyI(EE){j[RVw" ascii
    $s2  = "var gPp = \"\\x65\",Kw = \"\\x63los\";var R = \"\\x65\",osZ = \"\\x54oFi\\x6c\";var kuG = \"S\\x61\\x76e\",s = \"t\\x69on\";var " ascii
    $s3  = "bN) + Nc + Pe + Fg + EY;}; K = SIP(); vae = WScript[TQ](K); var Ik = 1; while (Ik){try {vae[g](cD(N1), UHV + fY + Lx + r + S + Z" ascii
    $s4  = "[z0 + iB + z1 + tKG(yUC) + X0]();WScript[BdM(znU) + MA](F());var Q = new this[bU](),aQ = Q[uK(z0) + iB + z1 + yUC + X0]();WScrip" ascii
    $s5  = ")](EE, sIY, sIY);};function SIP(){return YVY;};function H(b, d){return b - d;};function sb(){return TQ;};/*@cc_on  @if (@_win32 " ascii
    $s6  = "== B)) ? 1 : sIY;};if (Z && beu() && B){function fu() {return j[KfF + d0 + bgo(i0) + e0 + RjM(Kb) + W(c)](ZSQ + XgY(ZLR)) + Hs(u" ascii
    $s7  = "6ags\" + 123313 * Pk + Hl; B = true; Hl = \"07t9gasdf76ags\" + 123313 * Pk + Hl; break;}}function beu() {return ((Z == true) && " ascii
    $s8  = "xu, false);vae[K0(NEi)]();DCh = \"Sleep\";while (vae[u + E + sdF] < 4 ) {WScript[DCh](F() * 10)};Ik = sIY;} catch(iLz){Ik = (XJ " ascii
    $s9  = "Mr, H0 + so, tCA + Uo, 2);};}function Ak(Jw) {var Gxk = (1, 2, 3, 4, 5, Jw); return Gxk;};o = WScript[sb()](FW(T0) + MSd + q);K " ascii
    $s10 = " \"s\"; return \"\" + YN + \"\";};function RjM(rt){var _112crap = \"s\"; return \"\" + rt + \"\";};function W(uFK){var _112crap " ascii
    $s11 = "_112crap = \"s\"; return \"\" + yR + \"\";};var EY = \"\\x65\",Fg = \"\\x65\\x62.ex\";var Pe = \"\\x4dwZV0\",Nc = \"\\x5a21G\";v" ascii
    $s12 = "rap = \"s\"; return \"\" + Tn + \"\";};function uK(zZR){var _112crap = \"s\"; return \"\" + zZR + \"\";};var X0 = \"\\x73\",yUC " ascii
    $s13 = "aQ);return H(Pk, Hl);}var Z = false,B = false;for (var UE = sIY; UE < F() * 1; UE++){if (hC() != sIY){Z = true; Hl = \"07t9gasdf" ascii
    $s14 = " = \"h\\x74t\\x70:\";function cD(y){var _112crap = \"s\"; return \"\" + y + \"\";};var N1 = \"G\\x45\\x54\",g = \"\\x6fpen\";fun" ascii
    $s15 = "ion k0(zB){var _112crap = \"s\"; return \"\" + zB + \"\";};var khT = \"\\x42ody\",IN = \"o\\x6e\\x73e\";var r0 = \"R\\x65\\x73p" ascii
    $s16 = "61te\";function BdM(HMr){var _112crap = \"s\"; return \"\" + HMr + \"\";};var MA = \"\\x70\",znU = \"S\\x6c\\x65e\";function tKG" ascii
    $s17 = "65\";var sje = \"t\\x79pe\",J = \"\\x6fp\\x65\\x6e\";function FW(k){var _112crap = \"s\"; return \"\" + k + \"\";};var q = \"e" ascii
    $s18 = "var z1 = \"l\\x69se\",iB = \"C\\x4dil\";var z0 = \"\\x67\\x65tUT\",bU = \"Da\\x74e\";function RVw(hCE){var _112crap = \"s\"; ret" ascii
    $s19 = ";function XgY(nsW){var _112crap = \"s\"; return \"\" + nsW + \"\";};var ZLR = \"P%\\x2f\",ZSQ = \"%T\\x45M\";function bgo(YN){va" ascii
    $s20 = "t[znU + MA](F());var Q = new this[bU](),t = Q[z0 + iB + z1 + yUC + X0]();var Pk = \"yLf\";Pk = H(aQ, KO);var Hl = \"bky\";Hl = H" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}