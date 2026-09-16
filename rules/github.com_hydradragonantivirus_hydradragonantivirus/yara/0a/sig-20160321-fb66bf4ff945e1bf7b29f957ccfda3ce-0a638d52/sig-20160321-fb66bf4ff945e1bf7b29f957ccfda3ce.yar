rule sig_20160321_fb66bf4ff945e1bf7b29f957ccfda3ce {
  meta:
    description = "datamaliciousorder - file 20160321_fb66bf4ff945e1bf7b29f957ccfda3ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb3fb9a83830709e8964899a53d2f5571b25475ee6835b65a3e0fd458c7ef59"

  strings:
    $x1  = "function QHM(Hw){return Hw;};var U = \"162\";var xFb = \"68\";var tMLPQ = \"2183\";function XIsBR(Hn){return Hn;};function wIg(w" ascii
    $s2  = "ion jxlqG(){return pBWB;}()) + NeX(Jr) + (function wdy(){return No0;}()) + (function byfNo(){return QN;}())] < 4 ) {WScript[(fun" ascii
    $s3  = "}()) + (function pD(){return m;}()) + MOQTX(l0) + (function lnF(){return ak;}()) + (function daY(){return uPawu;}())]();WScript[" ascii
    $s4  = "vUzq); C = cgv(); j = WScript[zGQUU + (function COvf(){return aGFj;}()) + YyFcx + do0](C); var zp = true; while (zp){try {j[eJ(q" ascii
    $s5  = "tF + (function KIhes(){return IER;}());};function owDdx(sk, cEIJA){return sk - cEIJA;};function ud(){return zGQUU + s(aGFj) + (f" ascii
    $s6  = "Rb = \"E\\x63\";function KZK(R){return R;};var y = \"%/\";var hv = \"%TEMP\";function KB(UNDBw){return UNDBw;};function Jhk(s1){" ascii
    $s7  = "ction mb(){return DmeU;}()) + qG(hf)](xtVM() * 10)};zp = false;} catch(e){};}q = WScript[ud()](FKA + Cx + gp + pM + hvllH(HMam))" ascii
    $s8  = "var zbyd = \"Crea\\x74\";function ao(rT){return rT;};function z(f){return f;};var Xg = \"o4fP4\";var IER = Xg[\"ch\\x61rAt\"](3)" ascii
    $s9  = "ywb4tJ792u\";var QN = \"\\x61t\\x65\";var No0 = TZJ[\"ch\\x61rAt\"](4);var Jr = \"\\x79s\";var pBWB = \"rea\\x64\";function hsR(" ascii
    $s10 = "){return HcH;};var r = \"\\x44\\x61t\\x65\";var rUtj = \"VkIeF\";var bLvG = \"\\x63t\";var sr = rUtj[\"ch\\x61rAt\"](3);var L = " ascii
    $s11 = "n hvllH(OQ){return OQ;};var yAJJB = \"UUaM\";var RTkw = \"QmtNmX69\";var HMam = RTkw[\"ch\\x61rAt\"](4);var pM = yAJJB[\"ch\\x61" ascii
    $s12 = "ction DaUD(MA){return MA;};var BwUZI = \"o0Heuw\";var P0 = BwUZI[\"ch\\x61rAt\"](3);var WN = \"t\\x79p\";var LaOM = \"\\x6fp\\x6" ascii
    $s13 = "LlF = \"GET\";function eJ(WZ){return WZ;};function HkKN(WWoUr){return WWoUr;};var wBqTn = \"\\x65n\";var qmLLo = \"o\\x70\";var " ascii
    $s14 = "(wz, 0, 0);};function cgv(){return (function CQt(){return YZB;}()) + ao(I) + z(tBkh) + (function XOfOE(){return V;}()) + w + Mpz" ascii
    $s15 = ";zJR(AhfwU);i = \"\" + QtBt(fDaB) + kslS(WYZ) + (function TmMOV(){return y0;}()) + (function yUGv(){return DwY;}()) + ytupG(OZ) " ascii
    $s16 = " + l ? XIsBR(scMn) + wIg(ZlXcw) + pPds + cn + TF(whR) : (function w1(){return tMLPQ;}()) + QHM(xFb) + (function ILjm(){return U;" ascii
    $s17 = "unction CR(){return YyFcx;}()) + (function iE(){return do0;}());};function xtVM(){return 22;};function jx(){var ApF = new this[r" ascii
    $s18 = " + zu + (function v(){return fNr;}()) + (function yZqmP(){return ZxZQH;}()) + g(HG), false);j[hsR(Et) + ziMTa]();while (j[(funct" ascii
    $s19 = "(function QAhvj(){return JBI;}()) + bqEuF(EXMLd) + Ylr + hp + (function FbU(){return Aqr;}()) + (function QFyNe(){return Ho;}())" ascii
    $s20 = "]();var xBwzp = ApF[EW + Xo(qiLA) + qS(m) + (function Ab(){return l0;}()) + (function OKoS(){return ak;}()) + QLCP(uPawu)]();WSc" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}