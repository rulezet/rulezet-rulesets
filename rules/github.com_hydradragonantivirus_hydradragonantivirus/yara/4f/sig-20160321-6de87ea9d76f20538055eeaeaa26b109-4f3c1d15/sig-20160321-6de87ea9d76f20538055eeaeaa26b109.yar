rule sig_20160321_6de87ea9d76f20538055eeaeaa26b109 {
  meta:
    description = "datamaliciousorder - file 20160321_6de87ea9d76f20538055eeaeaa26b109.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "121218cb600dc02f31f163457e8d838bd33d06598b6e8350a4f22f01e4b29322"

  strings:
    $s1  = "var A0 = \"KMQpA2\";var Yz = \"16\\x32\";var xXPXS = \"1\\x38368\";var rYd = A0[\"charAt\"](5);var d0 = \"\\x66asd\\x66\";var Nt" ascii
    $s2  = ") {return WScript[(function upLa(){return Hbas;}()) + PW(y) + c(bn) + nIma(UUpH)](UJ + fu + (function cFRn(){return sz;}()) + QL" ascii
    $s3  = " Q0, false);yn[qp(E0)]();while (yn[LPNko(tDeJ) + tkNv(E1) + AAh(TXU) + xFw(jxMwv) + oSzZz(yzz) + Nwjc] < 4 ) {WScript[I2(WcUWv)]" ascii
    $s4  = "return GkM;}()) + ddsQe(w2); u = ye(); yn = WScript[Hbas + jHE(y) + (function KceX(){return bn;}()) + UUpH](u); var I = true; wh" ascii
    $s5  = "this[(function yWk(){return Rvbx;}())]();var Md = rpOZ[H(Tf) + z + ghFrT + xDa(FOn) + NSXNb]();WScript[(function zxcx(){return W" ascii
    $s6  = "nction pLS(){return wbtQd;}()) + (function MlV(){return w;}());};function rgY(a, sx){return a - sx;};function sH(){return Hbas +" ascii
    $s7  = "= true;break;}}function Lqct() {return Fh && VhCcg;};if (Lqct()){E = GA[Uw(jagQ) + (function HQI(){return muUB;}()) + UMwW + XHD" ascii
    $s8  = "(Ac() * 10)};I = false;} catch(e){};}agcTK = WScript[sH()]((function wgJ(){return u0;}()) + (function knHy(){return dvhvN;}()) +" ascii
    $s9  = "))]();WScript[(function cSO(){return WcUWv;}())](Ac());var rpOZ = new this[(function Q(){return Rvbx;}())]();var Kc = rpOZ[(func" ascii
    $s10 = "r C = \"hO5nwD\";var iy = \"ate\";var YSrSd = C[\"charAt\"](5);function I2(EfKD){return EfKD;};var WcUWv = \"Sleep\";function H(" ascii
    $s11 = "[\"charAt\"](5);function E2(FpQ){return FpQ;};function XP(krLIK){return krLIK;};var ULX = \"y\";var cucb = \"\\x42o\\x64\";var C" ascii
    $s12 = "\"Cpf\";var ByXjQ = \"c\\x74\";var LG = \"eO\\x62j\\x65\";var l = \"ea\\x74\";var eCe = \"\\x72\";var w0 = IQNW[\"charAt\"](0);f" ascii
    $s13 = "qo(JUJp){return JUJp;};var mcB = \"kNTkvB\";var OSg = \"oFile\";var M = mcB[\"charAt\"](2);var V1 = \"S\\x61v\\x65\";function fJ" ascii
    $s14 = ";};function h0(ExaT){return ExaT;};function Jot(ehhMf){return ehhMf;};var NZ = \"TnPg0\";var NSXNb = \"ds\";var FOn = NZ[\"charA" ascii
    $s15 = "VD = \"PErvBeYWqbM\";var w2 = VD[\"charAt\"](5);var GkM = \"Z\\x2e\\x65x\";var SYS = \"4Mh\\x62L\";var y0 = \"vxwf\\x4d\";functi" ascii
    $s16 = " = \"t\";var jxMwv = \"sta\";var TXU = \"ady\";var E1 = \"e\";var tDeJ = tKh[\"charAt\"](5);function qp(V0){return V0;};var E0 =" ascii
    $s17 = "{return iZbKN;};function EyDc(A){return A;};var P = \"8DjQg\";var w1 = \"\\x73\";var Pbrj = P[\"charAt\"](4);var b = \"rin\";var" ascii
    $s18 = "xvT = wP[\"charAt\"](1);var o = \"\\x53\\x6ce\\x65\";function LPNko(Iffi){return Iffi;};function tkNv(KWtmm){return KWtmm;};func" ascii
    $s19 = "cUWv;}())](Ac());var rpOZ = new this[vuroj(Rvbx)]();var Z = rpOZ[Tf + z + Y(ghFrT) + AHKm(FOn) + (function ROb(){return NSXNb;}(" ascii
    $s20 = " (function Jc(){return y;}()) + (function UlCnB(){return bn;}()) + UUpH;};function Ac(){return 22;};function r(){var rpOZ = new " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}