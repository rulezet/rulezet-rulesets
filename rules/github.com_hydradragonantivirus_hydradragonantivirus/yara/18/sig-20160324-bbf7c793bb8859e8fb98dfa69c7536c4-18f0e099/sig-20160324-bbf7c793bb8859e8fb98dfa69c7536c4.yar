rule sig_20160324_bbf7c793bb8859e8fb98dfa69c7536c4 {
  meta:
    description = "datamaliciousorder - file 20160324_bbf7c793bb8859e8fb98dfa69c7536c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd818bdab78ce67683f42b830a2ab38a5b949f09cca8b1c69147e973fdcbf9af"

  strings:
    $s1  = "function K0(CHR){var _112crap = \"s\"; return \"\" + CHR + \"\";};var k = \"\\x63l\\x6f\\x73\\x65\";function ywL(Dnn){var _112cr" ascii
    $s2  = "CreateObject\";var cX = function yTe() {return WScript[cDj](Yg(oJL) + z + bx(LuB));}();var kv = 123213,uo = \"MSXML2.XMLHTTP\";v" ascii
    $s3  = ", 4, 5, Mj); return sny;};uDA = WScript[ri()](gQ + x0 + n0);Mr = uDA;Mr[(jM)]();Mr[t(wvq)] = D(1);Mr[ne(DnQ)](Nf[E0 + KIJ + x1(M" ascii
    $s4  = " VL(w) + G0(lzo) + RHP + SQp](lkS + oBU(r1)) + bQG + cl + P;}; Mr = Hg(); Nf = WScript[cDj](Mr); var Jds = 1; while (Jds){try {N" ascii
    $s5  = "on hK(){var mH = new this[X](),dH = mH[gSc + jDQ + Ing + Bn]();WScript[E + XH](ek());var mH = new this[X](),sO = mH[AI(gSc) + rv" ascii
    $s6  = "\" + y + \"\";};var Bn = \"on\\x64\\x73\",Ing = \"\\x69s\\x65c\";var jDQ = \"CMi\\x6c\\x6c\",gSc = \"getU\\x54\";function cYx(G)" ascii
    $s7  = "QNu = 2123213,c = 0;function azs(AA){cX[h](AA, c, c);};function Hg(){return uo;};function s(Wj, Z){return Wj - Z;};function ri()" ascii
    $s8  = "qR; break;}}function A() {return ((dc == true) && (dc == Xn)) ? 1 : c;};if (dc && A() && Xn){function A0() {return cX[AuM + z0 +" ascii
    $s9  = "Script[DV](ek() * 10)};Jds = c;} catch(K){Jds = (zVK + QV, n(m) + G1(y0), Ma + dk(MuF), 2);};}function D(Mj) {var sny = (1, 2, 3" ascii
    $s10 = "(jDQ) + FEZ(Ing) + Bn]();WScript[E + XH](ek());var mH = new this[cYx(X)](),Cae = mH[rk(gSc) + YR(jDQ) + Ing + cud(Bn)]();var r0 " ascii
    $s11 = "\\x78e\",cl = \"Z7\\x41IA\";var bQG = \"Y7\\x44c\";function oBU(IUz){var _112crap = \"s\"; return \"\" + IUz + \"\";};var r1 = " ascii
    $s12 = "ap = \"s\"; return \"\" + FLd + \"\";};var y0 = \"a\\x73\\x64\\x66\",m = \"f\\x61df\";var QV = \"\\x61\",zVK = \"\\x61sdf\";func" ascii
    $s13 = "\"; return \"\" + G + \"\";};var X = \"\\x44ate\",h = \"Ru\\x6e\";var NX = \"\\x50\",f = \"\\x4cH\\x54\\x54\";var ci = \"2.\\x58" ascii
    $s14 = "xY = \"\\x72eady\",d = \"\\x70\";var H0 = \"S\\x6ce\\x65\",oBm = \"se\\x6ed\";function O(TgB){var _112crap = \"s\"; return \"\" " ascii
    $s15 = "112crap = \"s\"; return \"\" + zc + \"\";};function FEZ(e){var _112crap = \"s\"; return \"\" + e + \"\";};function rk(QgL){var _" ascii
    $s16 = "f[jM](aC, O(hC) + xV + eI + Xyd + r2 + Y(c0) + dBx + IL, false);Nf[oBm]();DV = \"Sleep\";while (Nf[MN(xY) + vLw(pe) + BX] < 4 ) " ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + Rj + \"\";};var Ma0 = \"\\x6fdy\",KIJ = \"ons\\x65B\";var E0 = \"R\\x65sp\";function ne(WcL" ascii
    $s18 = " sy + \"\";};var MuF = \"\\x61\",Ma = \"afd\\x61f\";function n(MT){var _112crap = \"s\"; return \"\" + MT + \"\";};function G1(F" ascii
    $s19 = "; r++){if (hK() != c){dc = true; nqR = \"07t9gasdf76ags\" + 123313 * r0 + nqR; Xn = true; nqR = \"07t9gasdf76ags\" + 123313 * r0" ascii
    $s20 = "function K0(CHR){var _112crap = \"s\"; return \"\" + CHR + \"\";};var k = \"\\x63l\\x6f\\x73\\x65\";function ywL(Dnn){var _112cr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}