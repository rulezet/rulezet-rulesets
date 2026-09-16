rule sig_20160318_d471ea8e23a647865908acab7b4b791d {
  meta:
    description = "datamaliciousorder - file 20160318_d471ea8e23a647865908acab7b4b791d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6c9ab430d2313033449df0f4502c04bba48896e123a8155211bd289c84235d"

  strings:
    $s1  = "var G0 = \"\\x61in!\";var y = \"\\x61g\";var Sx = \"\\x72y \";var HD = \", t\";var ABjk = \"\\x61\\x73e\";var xUf = \"Pl\\x65\";" ascii
    $s2  = "+ (function TqGjU(){return RlJ;}())]();WScript[(function phKkM(){return R;}()) + (function qZpTo(){return gdQ;}())](Fd());var I " ascii
    $s3  = "}()) + (function GRu(){return OfLp;}()) + (function Y2(){return AG;}()) + (function pnX(){return Q;}());}else{WScript.Echo((func" ascii
    $s4  = "function KzWUt(){return wsXLW;}()) + (cYI)] < 4 ) {WScript[(R) + (function FEvIP(){return gdQ;}())](Fd() * 10)};uMz = WScript[Cx" ascii
    $s5  = " (Kha) + (function CF(){return RlJ;}())]();WScript[(function YNt(){return R;}()) + (function wpZ(){return gdQ;}())](Fd());var I " ascii
    $s6  = "urn NM;}()) + (function KvmAc(){return CdGbU;}()) + (QilQ); NO = ly(); MP = WScript[(function zNVl(){return qIX;}()) + (function" ascii
    $s7  = "Script[(qIX) + (function yEEjR(){return j;}()) + (function GEGc(){return wvV;}()) + (function VCBEb(){return yc;}()) + (function" ascii
    $s8  = " (function C0(){return idP;}());};function njah(agO, uyJ){return agO - uyJ;};function Cx(){return (function GBJz(){return qIX;}(" ascii
    $s9  = "yyO = true;break;}}function hQV() {return Gc && yyO;};if (hQV()){SgyFf = IFw[(function YkY(){return Gb;}()) + (function sskl(){r" ascii
    $s10 = " DbC = \"ztCMBl\"[\"charAt\"](1);var yc = \"ec\";var wvV = \"b\\x6a\";var j = \"ateO\";var qIX = \"Cre\";var IFw = function YMms" ascii
    $s11 = "vii = \"Slee\\x70\";var cYI = \"weT\"[\"charAt\"](1);var wsXLW = \"\\x73\\x74at\";var N = \"y\";var CPvF = \"\\x72e\\x61\\x64\";" ascii
    $s12 = ") + (function EXe(){return RlJ;}())]();var tYojn = \"URbPH\";tYojn = njah(IoIop, B);var mnyY = \"zyWwe\";mnyY = njah(uqn, IoIop)" ascii
    $s13 = "){var I = new this[(Gq) + (function WTMyv(){return CPI;}()) + (function p(){return Rfuk;}())]();var B = I[(function LpZw(){retur" ascii
    $s14 = ")), false);MP[(function QfmDX(){return sLaNg;}())]();while (MP[(function e(){return CPvF;}()) + (function R0(){return N;}()) + (" ascii
    $s15 = "dTe;}()) + (eci) + (function S(){return fNKqy;}()) + (function aH(){return MGL;}()) + (dPPr) + (function ikWe(){return Kha;}()) " ascii
    $s16 = "n SXbic(){return Gkel;}())] = 0;uMz[(function vW(){return yWjF;}()) + (function RDoD(){return PtEQS;}()) + (function yE(){return" ascii
    $s17 = "= new this[(function vPGLF(){return Gq;}()) + (function G(){return CPI;}()) + (Rfuk)]();var uqn = I[(function QZnae(){return led" ascii
    $s18 = "tion Yg(){return xUf;}()) + (function NfXfS(){return ABjk;}()) + (function y0(){return HD;}()) + (function ffYt(){return Sx;}())" ascii
    $s19 = "on Lghb(){return Ds;}()) + (function ljT(){return p0;}())]((function Y0(){return tqJ;}()) + (Hmzg)) + (vZlo) + (function T(){ret" ascii
    $s20 = "n = \"\" + (YIlV) + (function ryDR(){return xGxAB;}()) + (function AtWJv(){return J0;}()) + (function ggxtG(){return wJ;}()) + (" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}