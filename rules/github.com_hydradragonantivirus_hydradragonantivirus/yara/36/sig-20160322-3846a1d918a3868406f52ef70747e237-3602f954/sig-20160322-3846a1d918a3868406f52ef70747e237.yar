rule sig_20160322_3846a1d918a3868406f52ef70747e237 {
  meta:
    description = "datamaliciousorder - file 20160322_3846a1d918a3868406f52ef70747e237.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa4a142608d136d8e5f87780f0fb512d2c007893456e9a56dc2e1464520db7d3"

  strings:
    $s1  = "function TfzM(qrAPw){return qrAPw;};function Coa(Kvdox){return Kvdox;};function Maxdz(q0){return q0;};var Yr = \"71\";var vhEi =" ascii
    $s2  = ";}()) + (function u0(){return q;}())]();while (YRZyV[Zx(hEpfG) + yuNd + pRa(usAv)] < 4 ) {WScript[(function UVEL(){return J;}())" ascii
    $s3  = ")) + (function XsZu(){return isyL;}()) + X(tAK) + WeKS(oFJJQ)]();WScript[J + UwQPD(VXQr)](VmF());var HCZzW = new this[h(RS) + (f" ascii
    $s4  = "TIs(){return oFJJQ;}())]();WScript[J + bvjU(VXQr)](VmF());var HCZzW = new this[(function iH(){return RS;}()) + dm(bWJJA)]();var " ascii
    $s5  = "on Neqrk() {return WScript[EBt + M0 + Rkt](rYHCn + Y + sRv + UWd(PR));}();function CpS(kN){SeM[(function Znym(){return Rc;}())](" ascii
    $s6  = "Q;}()) + (function Oj(){return C;}()) + OqU(Wz) + WEp + (function ZHy(){return GvW;}()); f = fNwv(); YRZyV = WScript[EBt + Xc(M0" ascii
    $s7  = "nction OeV(){return e1;}());};function oZX(nfHou, sBOY){return nfHou - sBOY;};function lpTDQ(){return (function oP(){return EBt;" ascii
    $s8  = "rue;Xhy = true;break;}}function e() {return s && Xhy;};if (e()){YPd = SeM[PQgE(mo) + Kx + mosR(W) + e2(dEqXv) + td(eIqw) + (func" ascii
    $s9  = " + bhdg(VXQr)](VmF() * 10)};YouY = false;} catch(e){};}ajvx = WScript[lpTDQ()](VnKwG + kkq(aXSC) + XAiYn + uJp + (function VHC()" ascii
    $s10 = "n Uysfk(){return lCs;}()) + TfzM(Vyes) + Coa(E0) + Maxdz(vhEi);}" fullword ascii
    $s11 = "= \"e\\x6ed\";var kf = EgWq[\"c\\x68\\x61rAt\"](4);function YbnaA(QuF){return QuF;};function wH(ybPzC){return ybPzC;};function N" ascii
    $s12 = "XSC = \"\\x44\";var VnKwG = \"A\\x44O\";var n0 = \"ep6NBe0\";var FHvgW = n0[\"c\\x68\\x61rAt\"](1);var T1 = \"Sl\\x65\\x65\";fun" ascii
    $s13 = "\"v9HC4t6\";var RoA = \"e\\x63\\x74\";var A = \"t\\x65\\x4f\\x62j\";var Csln = \"rea\";var IMZz = U[\"c\\x68\\x61rAt\"](3);funct" ascii
    $s14 = "){return rElH;};var yApAt = \"HiiPUYJ3\";var s0 = \"d\";var B = \"ROsVW\";var oFJJQ = B[\"c\\x68\\x61rAt\"](2);var tAK = s0[\"c" ascii
    $s15 = "62\";var E0 = Yr[\"c\\x68\\x61rAt\"](1);var Vyes = \"68\";var lCs = \"2183\";function O0(jvJ){return jvJ;};var z = \"df\";var V0" ascii
    $s16 = " = \"hIi732\";var NpUfD = \"c\";var tyEe = \"\\x73\";var uUI = \"gda\";var XfBc = Ul[\"c\\x68\\x61rAt\"](0);var oDOdg = \"/\\x32" ascii
    $s17 = ";}()) + XgOe + bWL + IeUnl(y0) + w1(LQ) + awJ + i0 + slUaG(R) + s ? tH + (function HYzZ(){return IS;}()) + V0 + O0(z) : (functio" ascii
    $s18 = ") + Rkt](f); var YouY = true; while (YouY){try {YRZyV[H + dz(BRb)](nuH + VHJn, (function h0(){return O;}()) + YbnaA(zt) + wH(gNX" ascii
    $s19 = "function zYPJB(){return XfBc;}()) + uUI + tvv(tyEe) + (function Ic(){return NpUfD;}()), false);YRZyV[(function Cizzr(){return kf" ascii
    $s20 = "}()) + a(M0) + (function dakFZ(){return Rkt;}());};function VmF(){return 22;};function FlYd(){var HCZzW = new this[fatSV(RS) + (" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}