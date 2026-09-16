rule sig_20160321_d5c45fa54cd1d4cf6a0edda94a079751 {
  meta:
    description = "datamaliciousorder - file 20160321_d5c45fa54cd1d4cf6a0edda94a079751.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6499f1819dee0009653dce0b21aed03df74d77c376f0f6a87444ea45e374250"

  strings:
    $x1  = "function wqhH(S0){return S0;};var mYl = \"8\\x31\\x362\";var KwCaQ = \"21\\x3836\";var XJQJP = \"s\\x64\\x66\";var Z = \"\\x66a" ascii
    $s2  = "rAt\"](0);var zFD = \"/a\";var sDLLp = Rqz[\"\\x63harAt\"](2);var LVXg = \"\\x68\\x74tp:\";var ey = \"\\x47ET\";function SsH(swP" ascii
    $s3  = " BLZ() {return WScript[z(D) + ezoA(oLCZH) + dNN + (function aR(){return i;}()) + (function m0(){return oaqY;}()) + WJPs(jMEkY)](" ascii
    $s4  = " My(){return vAp;}()) + (function Cg(){return OKeJO;}())]();WScript[(function eqjTP(){return lxmk;}()) + PYmnT(JD)](kybyl());var" ascii
    $s5  = "return wtA;}()) + H + URQB(E); mfCQk = sdvRa(); ckfxE = WScript[epPj(D) + oLCZH + rmDRe(dNN) + wIlXG(i) + (function jRmHT(){retu" ascii
    $s6  = "b(OKeJO)]();WScript[lxmk + JD](kybyl());var pb = new this[miKCm(VKKtc) + (function fuD(){return sTOQk;}())]();var p = pb[(functi" ascii
    $s7  = "+ xlv + SsH(ylJdP)](ey, kVdY(LVXg) + sDLLp + (function Rrk(){return zFD;}()) + UTru(vUDqG) + (function v0(){return b0;}()) + pMP" ascii
    $s8  = " R(C) + (function s(){return M0;}()) + Ta + d0;};function b(O, x){return O - x;};function Ymzu(){return (function nN(){return D;" ascii
    $s9  = "t\";var PB = \"a\";var Sqy = \"\\x43\\x72e\";function n(NC){return NC;};function URQB(Wo){return Wo;};var AQeh = \"fHFn0\";var E" ascii
    $s10 = " = true;UAC = true;break;}}function r() {return Tp && UAC;};if (r()){daMbq = CDYxy[(function nPl(){return ikFDt;}()) + RLU(MS0) " ascii
    $s11 = "cript[COOZF(lxmk) + JD](kybyl() * 10)};bp = false;} catch(e){};}emtE = WScript[Ymzu()]((function JENt(){return avwyY;}()) + DU0 " ascii
    $s12 = "NSc = msf[\"\\x63harAt\"](1);function jRLZ(lL){return lL;};function R(A0){return A0;};var d0 = \"TP\";var Ta = \"LH\\x54\";var M" ascii
    $s13 = ";var H = AQeh[\"\\x63harAt\"](2);var wtA = \"j\\x73S\\x6c\";var G = \"\\x6aJn\\x398\";var cuwkx = \"3b\\x74\";var J = \"4\";func" ascii
    $s14 = "\";var NjUih = \"g\";var xe = \"0qSstD4x\";var Fa = \"\\x61te\";var B0 = xe[\"\\x63harAt\"](5);function PYmnT(hHb){return hHb;};" ascii
    $s15 = "EkY = \"t\";var oaqY = \"ec\";var i = \"bj\";var dNN = \"O\";var oLCZH = \"rea\\x74\\x65\";var D = TZZS[\"\\x63harAt\"](0);var C" ascii
    $s16 = "var d1 = \"s\\x70o\\x6e\";var xZTJc = \"Re\";var yo = \"LqK2wMRvUS\";var X = \"e\";var i0 = \"ri\\x74\";var BTq = yo[\"\\x63harA" ascii
    $s17 = " At = \"se\";var yO = UrGM[\"\\x63harAt\"](5);var B2 = \"l\";var PmdBR = QGy[\"\\x63harAt\"](4);function EDsM(ooE){return ooE;};" ascii
    $s18 = "nction KgZd(GTG){return GTG;};var OKeJO = \"n\\x64\\x73\";var vAp = \"co\";var Pydqa = \"\\x6cl\\x69se\";var kF = \"getMi\";func" ascii
    $s19 = "4d\";var C = \"XM\\x4c2.\";var JXO = \"MS\";var YoNP = \"nqH\";var JN = YoNP[\"\\x63harAt\"](0);var JV = \"Ru\";function JSf(T){" ascii
    $s20 = ";emtE[glf + (function j0(){return galy;}())] = 0;emtE[(function wg(){return vwUgp;}()) + EDsM(O2) + (function XR(){return idrBF;" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}