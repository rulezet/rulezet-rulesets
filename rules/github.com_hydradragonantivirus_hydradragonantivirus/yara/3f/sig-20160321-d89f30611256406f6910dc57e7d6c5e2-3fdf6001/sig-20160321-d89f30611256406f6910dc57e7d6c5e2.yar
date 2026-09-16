rule sig_20160321_d89f30611256406f6910dc57e7d6c5e2 {
  meta:
    description = "datamaliciousorder - file 20160321_d89f30611256406f6910dc57e7d6c5e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c138db7d44ff42c3cd847ccc0e3e73cfe0c927a99316158ed6d31914e93403bf"

  strings:
    $s1  = "function P1(RijKN){return RijKN;};var NIql = \"816\\x32\";var L1 = \"\\x336\";var WFNL = \"218\";function ZmF(E){return E;};var " ascii
    $s2  = "return ZRy;}())]();WScript[(function e(){return gOM;}()) + AbeII(cZ)](h());var Q = new this[IPkr(PWyxK) + t]();var JtFS = Q[(fun" ascii
    $s3  = " Ozd) + J0(nSd) + (function txC(){return a;}()) + L0(FErx) + (function FxTJ(){return MtdH;}()); Cmw = ukJbc(); jnTUI = WScript[V" ascii
    $s4  = "ction BA(){return H;}()) + dABT(GC) + (function JFWv(){return elZ;}()) + (function xapLc(){return VepZ;}()) + g(ZRy)]();WScript[" ascii
    $s5  = "Jy + (function b(){return niyW;}());};function LiOCV(yZOF, VyW){return yZOF - VyW;};function N(){return (function Pld(){return i" ascii
    $s6  = "= true;break;}}function tG() {return Y0 && ig;};if (tG()){Y = doo[(function NSzxA(){return nE;}()) + oaEg(jGDf) + fa + (function" ascii
    $s7  = " ) {WScript[HqPO(gOM) + z0(cZ)](h() * 10)};JBKaO = false;} catch(e){};}ex = WScript[N()]((function hl(){return PT;}()) + (functi" ascii
    $s8  = "VU){return VPVU;};var wSAn = \"eIpj18n\";var mc = \"hell\";var bYY = \"t.S\";var DnQp = wSAn[\"charAt\"](2);var ilGdp = \"\\x57" ascii
    $s9  = "EHw7\";var niyW = \"\\x54T\\x50\";var dhEJy = uACOd[\"charAt\"](2);var Jy = \"L\";var dBW = \"\\x4c\\x32\\x2eXM\";var u = \"MSX" ascii
    $s10 = "j(D1){return D1;};function Tf(a1){return a1;};var mk = \"v9hvJg\";var x1 = \"d\\x66\";var dwNVT = \"is\";var C = mk[\"charAt\"](" ascii
    $s11 = "o = e0[\"charAt\"](1);var rgwKN = \"tat\";var BHeHP = \"ad\\x79s\";var yrRw = \"re\";function LRj(Z0){return Z0;};var qDh = \"nd" ascii
    $s12 = " = gD[\"charAt\"](5);function XZeXa(UaK){return UaK;};var HGH = \"le\";var foS = \"e\\x54oFi\";var fV = \"S\\x61v\";function x0(" ascii
    $s13 = " \"\\x63\\x74\";var pJn = \"eObje\";var yEa = xxna[\"charAt\"](4);var TuaP = \"\\x43\\x72ea\";function kj(VyuJ){return VyuJ;};va" ascii
    $s14 = " \"e\";var amw = jmYq[\"charAt\"](3);var fm = \"ri\";var lhrXU = LtYET[\"charAt\"](3);function kfbHc(Gu){return Gu;};function Wz" ascii
    $s15 = "var GC = \"i\";var H = \"getM\";function IPkr(ns){return ns;};var t = \"t\\x65\";var PWyxK = \"D\\x61\";var xxna = \"BN6mt6wvN\"" ascii
    $s16 = "H(Gfj){return Gfj;};var l = \"5QPn0qBJ\";var w = l[\"charAt\"](3);var k = \"\\x52u\";function NfSJ(aYJCP){return aYJCP;};functio" ascii
    $s17 = " (function dokq(){return jnnpp;}()))]();ex[kfbHc(lpk) + WzFL(rIpPU)] = 1;ex[(function LfmO(){return lhrXU;}()) + U0(fm) + (funct" ascii
    $s18 = ") + (function EkdA(){return VepZ;}()) + ua(ZRy)]();var KYiU = \"iSZM\";KYiU = LiOCV(JtFS, z);var aurWX = \"wrH\";aurWX = LiOCV(j" ascii
    $s19 = "ion WxtZ(){return I;}()) + (function MCY(){return y0;}()) + qcOW + wWF + Nsxh(Pn) + dt + xjg(C) + Hj(dwNVT) + Tf(x1) + Y0 ? ZmF(" ascii
    $s20 = "n Jyj;}()) + (function Jgi(){return XrwrO;}())]();KvgDI(Y);KYiU = \"\" + XxLAL + (function pOOEp(){return p0;}()) + P0(s) + (fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}