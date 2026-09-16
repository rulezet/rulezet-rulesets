rule sig_20160323_e6a5866d3cd56835e1d3170057cdda1f {
  meta:
    description = "datamaliciousorder - file 20160323_e6a5866d3cd56835e1d3170057cdda1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deaebb3cc552e74a5b4f82c5200b59485bf795c05a18c72258c7b9694254f13c"

  strings:
    $s1  = "var Mlx = \"\\x63lo\\x73e\";function r0(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};function Gf(QHp){var _112crap = \"s" ascii
    $s2  = "+ N3 + \"\";};var EQ = \"%I3w\",Jy = \"\\x50%/\";var Il = \"TEM\",vq = EQ[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](0);function N2" ascii
    $s3  = "u0) + LZE + Wl(SLL) + P0(m3)]();WScript[NwH(H1) + fT(hq) + D0(T0)](M());var V = new this[Lwd + fe](),bW = V[t(Xwv) + B(X) + zt(u" ascii
    $s4  = "0) + sUw(LZE) + y(SLL) + m3]();WScript[H1 + RE(hq) + J(T0)](M());var V = new this[pi(Lwd) + fe](),H = V[Xwv + j(X) + pc(u0) + LZ" ascii
    $s5  = "r(t2) + ha(iU) + TI + EYy(dC);}; EpR = m(); aLO = WScript[FzK + W(TPa) + rCd(g) + P(bx)](EpR); var bk = true; while (bk){try {aL" ascii
    $s6  = "4, 5, HN); return rB;};O = (c) ? 14134 : 414234;GY = WScript[x()](i6(i5) + X1(FN) + eW(yW));EpR = GY;v = (NJ) ? O : v;EpR[(vMt(N" ascii
    $s7  = "My = function LRr() {return WScript[kHx(FzK) + TPa + hQ(g) + yfD(bx)](T + uh(ur) + TaJ(Ox) + q(SAE) + OKz(H0));}();function phz(" ascii
    $s8  = " false);aLO[u2(ck)]();while (aLO[tx(kx) + I(LZ) + CCx(XuJ) + gX(nAX) + KnS(Iy)] < 4 ) {WScript[BMF(H1) + dL(hq) + w0(T0)](M() * " ascii
    $s9  = "x63\"+\"\"+\"\\x68\"+\"arAt\"](5);function kHx(MZA){var _112crap = \"s\"; return \"\" + MZA + \"\";};function hQ(ruT){var _112cr" ascii
    $s10 = "rAt\"](4),HZn = \"ateOb\";var wj = \"Cre\";function hUY(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};function kH(g0){var " ascii
    $s11 = "\"; return \"\" + hIs + \"\";};var UM = \"5WxGsLx64\",m3 = UM[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](4);var SLL = \"ec\\x6fnd\"" ascii
    $s12 = "turn \"\" + s + \"\";};function Ebe(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};var p = \"IqyVRnK\",L0 = p[\"\"+\"\\x63" ascii
    $s13 = "\"sRAnD\",X2 = YA[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](3);var Ly = \"sit\\x69o\",YN = \"po\";function Nxa(tTY){var _112crap =" ascii
    $s14 = " 123313 * O + v; break;}}function php() {return ((c == NJ) && (c == true)) ? true : false;};if (c && php() && NJ){function kj() " ascii
    $s15 = "\\x68\"+\"arAt\"](2),VHv = \"\\x75\\x32\\x62g\";var W1 = b0[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](0);function aK(N3){var _112c" ascii
    $s16 = "Iy = \"\\x61\\x74e\";var nAX = \"t\",XuJ = txA[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"arAt\"](4);var LZ = \"\\x65ady\",kx = \"\\x72\";f" ascii
    $s17 = "s\";var VQ = \"n\\x64\",ke = \"e\\x63\\x6f\";var L = \"\\x69\\x6cli\\x73\",Pe = \"\\x43M\";var i1 = \"getUT\",P1 = \"\\x65\";var" ascii
    $s18 = "x41\\x44\\x4fD\\x42\";function Dr(yu){var _112crap = \"s\"; return \"\" + yu + \"\";};var dk = \"a\",yuW = \"afdaf\";function hI" ascii
    $s19 = "turn \"\" + lE + \"\";};function r(PO){var _112crap = \"s\"; return \"\" + PO + \"\";};function ha(YV){var _112crap = \"s\"; ret" ascii
    $s20 = " _112crap = \"s\"; return \"\" + Df + \"\";};function Sc(Mm){var _112crap = \"s\"; return \"\" + Mm + \"\";};function Bm(VxJ){va" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}