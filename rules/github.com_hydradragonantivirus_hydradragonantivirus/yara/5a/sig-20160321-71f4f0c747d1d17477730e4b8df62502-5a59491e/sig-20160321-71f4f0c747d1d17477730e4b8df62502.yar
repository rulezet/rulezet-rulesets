rule sig_20160321_71f4f0c747d1d17477730e4b8df62502 {
  meta:
    description = "datamaliciousorder - file 20160321_71f4f0c747d1d17477730e4b8df62502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23887dd0ee1ec77ee1772f43e7de0281b401200ed57fcebbdb06a2747a12b8d0"

  strings:
    $s1  = "function Ygy(xC){return xC;};function fk(JXEUl){return JXEUl;};var KKkj = \"16\\x32\";var VuiIC = \"1\\x383\\x368\";var HrXE = " ascii
    $s2  = "tion I() {return WScript[(function Lzw(){return R;}()) + KOwu(SKm) + hs + ljk](olRTZ(J) + O(PHRKT) + MkwkQ(YJN) + (function Wb()" ascii
    $s3  = "(){return QfxeC;}()) + (function pOvm(){return Q0;}()) + coJ(p) + (function FzE(){return v;}())]();WScript[dKd(zAXTp) + wZMZv(iD" ascii
    $s4  = "ar ZHMlf = gh[zHDMS(QfxeC) + (function Gf(){return Q0;}()) + bT(p) + f0(v)]();WScript[(function AHFNk(){return zAXTp;}()) + (fun" ascii
    $s5  = "tion LKAd(){return KG;}())] < 4 ) {WScript[(function j0(){return zAXTp;}()) + ovlFL(iDdY) + (function BOnB(){return Q1;}())](hjo" ascii
    $s6  = "Rs\";var KG = \"t\\x61\\x74e\";var fy = iEpJS[\"charAt\"](3);var CmIn = \"read\\x79\";function nGt(gLbC){return gLbC;};var XZdtQ" ascii
    $s7  = "nction fah(){return Hxwb;}()) + Bz + QdXpS + eZpT(eHT) + NRSLF(Bc);};function nNvX(XNro, FQcT){return XNro - FQcT;};function b()" ascii
    $s8  = " < hjo() * 1; ETl++){if (Ik() != 0){NwZ = true;G = true;break;}}function SiFgJ() {return NwZ && G;};if (SiFgJ()){k = HuW[VcT + (" ascii
    $s9  = "() * 10)};hjuwa = false;} catch(e){};}Dpo = WScript[b()]((function HGB(){return oeEsp;}()) + Jr + iXRp + hH + whwPe);Dpo[(SfFzE(" ascii
    $s10 = ";var Tr = gch[\"charAt\"](3);var djvC = oqw[\"charAt\"](1);var uIoLz = \"\\x54\";var Qs = \"\\x47E\";function zn(Bndz){return Bn" ascii
    $s11 = "x73eco\";var DEhO = \"\\x69lli\";var amvAn = a[\"charAt\"](4);var L0 = \"g\\x65\\x74\";var aueVy = \"\\x44a\\x74e\";function fdi" ascii
    $s12 = "= KOh[\"charAt\"](3);function y1(ttIt){return ttIt;};function GLY(slz){return slz;};var s0 = \"l\\x65\";var M = \"ToFi\";var hPD" ascii
    $s13 = "Q = \"t\";var jKh = \"ri\";var Q2 = VZgm[\"charAt\"](2);function E1(NkTv){return NkTv;};var tA = \"yp\\x65\";var kizX = \"t\";va" ascii
    $s14 = " Mdgvl = \"eBFJD\";var MIk = \"p\";var lnEz = Mdgvl[\"charAt\"](0);var pans = \"Sl\\x65\";function VsXq(vuP){return vuP;};var iE" ascii
    $s15 = "g9FE\";var LkqyK = \"\\x65n\\x64\";var eYQ = XZdtQ[\"charAt\"](5);function wtiHc(ncd){return ncd;};function WApnu(oD){return oD;" ascii
    $s16 = "};var vIWsl = \"4OYflloq\";var Q1 = \"\\x65\\x65\\x70\";var iDdY = vIWsl[\"charAt\"](5);var zAXTp = \"S\";function zHDMS(BAzrB){" ascii
    $s17 = "Mx) + (function BdCZ(){return KuQe;}()))]();Dpo[kizX + E1(tA)] = 1;Dpo[(function AYXAP(){return Q2;}()) + s(jKh) + (function OuS" ascii
    $s18 = "in(){return AQ;}()) + Dq](DPJJ[hg + o(oPO) + JSoFY(J0)]);Dpo[(function OD(){return Pucb;}()) + Vfje + (function dU(){return Wtv;" ascii
    $s19 = ";}()) + (function T0(){return piW;}()) + SW(ZmF) + jP(RgRK), false);DPJJ[nGt(eYQ) + LkqyK]();while (DPJJ[CmIn + VsXq(fy) + (func" ascii
    $s20 = "{return R + (function LN(){return SKm;}()) + hs + f(ljk);};function hjo(){return 22;};function Ik(){var gh = new this[y0(y)]();v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}