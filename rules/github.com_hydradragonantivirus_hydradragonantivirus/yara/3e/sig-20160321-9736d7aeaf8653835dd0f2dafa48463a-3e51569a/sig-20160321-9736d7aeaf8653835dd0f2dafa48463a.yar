rule sig_20160321_9736d7aeaf8653835dd0f2dafa48463a {
  meta:
    description = "datamaliciousorder - file 20160321_9736d7aeaf8653835dd0f2dafa48463a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c190d6554e19d69f44c03056d4cd3c67b25f10a56ec7da8d331861fc39c87405"

  strings:
    $s1  = "function HfAyr(TF){return TF;};var pVzti = \"Lqk3rc\";var CG = \"2\";var n2 = \"6\\x38\\x31\\x36\";var CY = pVzti[\"ch\\x61rAt\"" ascii
    $s2  = " YG = \"re\";var gP = \"C\";var flvkr = function bqnJ() {return WScript[WCGLJ(gP) + (function l(){return YG;}()) + wNMFe + (func" ascii
    $s3  = " fde + JpKb + bZ(fPHT) + pHF(fyLPT)]();WScript[(function NHJkv(){return qO;}()) + (function scb(){return WBGj;}())](zhHKR());var" ascii
    $s4  = "et;}()) + (function TFn(){return BrJAI;}()) + (function vI(){return vkn;}()); iC = Hhs(); qV = WScript[aoD(gP) + (function NJ(){" ascii
    $s5  = "tion kuGu(){return fyLPT;}())]();WScript[VWCDt(qO) + WBGj](zhHKR());var XDaJs = new this[(function t0(){return nIKXI;}())]();var" ascii
    $s6  = "while (qV[(function QX(){return TeZi;}()) + (function QtDX(){return SHLU;}()) + v(ONlmB) + rq0] < 4 ) {WScript[QjpOd(qO) + (func" ascii
    $s7  = "O);};function YD(q, FKKxX){return q - FKKxX;};function kRd(){return (function CLBgd(){return gP;}()) + YG + wNMFe + Xk;};functio" ascii
    $s8  = "false;for (var pr = 0; pr < zhHKR() * 1; pr++){if (VYR() != 0){HbwE = true;HK = true;break;}}function J() {return HbwE && HK;};i" ascii
    $s9  = "tion WV(){return WBGj;}())](zhHKR() * 10)};RoTL = false;} catch(e){};}b = WScript[kRd()](x(vf) + P + (function RB(){return IOW;}" ascii
    $s10 = "61rAt\"](2);var tsm = \"Sa\\x76e\\x54\";function DetF(NF){return NF;};function M(MZU){return MZU;};function pwO(C){return C;};va" ascii
    $s11 = " = \"2\\x31\\x38\";var SgR = \"ycWOdgy\";var UhGW = \"fasdf\";var XV = SgR[\"ch\\x61rAt\"](4);var hZ = \"a\\x73\";function E(p0)" ascii
    $s12 = "function HfAyr(TF){return TF;};var pVzti = \"Lqk3rc\";var CG = \"2\";var n2 = \"6\\x38\\x31\\x36\";var CY = pVzti[\"ch\\x61rAt\"" ascii
    $s13 = "PILI = \"l\";var ir = uqxXo[\"ch\\x61rAt\"](0);var MBB = \".S\\x68e\";var lDqQ = \"p\\x74\";var WNdm = \"\\x72i\";var aJL = \"S" ascii
    $s14 = "JZZrf[\"ch\\x61rAt\"](4);function WCGLJ(gEPU){return gEPU;};function aoD(q0){return q0;};var Xk = \"\\x62ject\";var wNMFe = \"at" ascii
    $s15 = "M\";function TryD(GcGD){return GcGD;};var KeIq = \"R6\";var AGQr = \"n\";var kVfss = \"u\";var oxMM = KeIq[\"ch\\x61rAt\"](0);fu" ascii
    $s16 = " = gaZI[\"ch\\x61rAt\"](0);var oq = \"e\\x77j4\";var cd = \"om/c\";var MLr = \"c\\x6f.\\x63\";var rR = \"am\";var ICpb = yNx[\"c" ascii
    $s17 = "s\";var YS = ljO[\"ch\\x61rAt\"](5);var iWK = \"ge\\x74M\";function OOMrM(I){return I;};var nIKXI = \"Date\";var PHi = \"\\x65ct" ascii
    $s18 = " = \"e\\x74\";var ajYEl = IEx[\"ch\\x61rAt\"](4);var RU = \"Da\\x74\\x65\";function VWCDt(z){return z;};function QjpOd(L){return" ascii
    $s19 = "+ HbwE ? (function RuGl(){return hZ;}()) + (function VM(){return XV;}()) + UhGW : LpW + (function ox(){return CY;}()) + HfAyr(n2" ascii
    $s20 = " h = XDaJs[fbn(iWK) + (function Vv(){return YS;}()) + (function ntZu(){return fde;}()) + JpKb + (function u(){return fPHT;}()) +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}