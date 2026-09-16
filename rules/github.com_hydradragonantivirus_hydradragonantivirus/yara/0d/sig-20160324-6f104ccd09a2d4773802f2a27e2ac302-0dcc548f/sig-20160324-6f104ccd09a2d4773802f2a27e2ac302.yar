rule sig_20160324_6f104ccd09a2d4773802f2a27e2ac302 {
  meta:
    description = "datamaliciousorder - file 20160324_6f104ccd09a2d4773802f2a27e2ac302.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5e226780be97fc1076f87247b5510ccfab1ac2e303945600ca6ec4723420ee4"

  strings:
    $s1  = "var GC = \"c\\x6c\\x6f\\x73e\",IA = \"oF\\x69le\";var R0 = \"Save\\x54\",Yuw = \"io\\x6e\";var qro = \"p\\x6fs\\x69t\",S = \"Bo" ascii
    $s2  = ") + xUU;}; xG = h(); Zzo = WScript[d](xG); var RH = 1; while (RH){try {Zzo[v0(I1)](zu(Ac), xm + bQ + Lw + Tv + KuT + B + Cjv, fa" ascii
    $s3  = ", Vx(j) + BI, 2);};}function gMn(YVo) {var ukT = (1, 2, 3, 4, 5, YVo); return ukT;};bvJ = WScript[NK()](jOw + DCK(uu) + e);xG = " ascii
    $s4  = ";var bSz = \"te\\x4fbj\",gLb = \"\\x43\\x72e\\x61\";var Klq = false,d = \"CreateObject\";var Mx = function wrK() {return WScript" ascii
    $s5  = ");WScript[IRI + Dum](cw());var oga = new this[wo(LT)](),wi = oga[Ohm(a0) + UD + m + SLj(kO)]();WScript[IRI + Dum](cw());var oga " ascii
    $s6  = "+ 123313 * Ej + PiZ; iyD = true; PiZ = \"07t9gasdf76ags\" + 123313 * Ej + PiZ; break;}}function AL() {return ((zHV == true) && (" ascii
    $s7  = "V == iyD)) ? 1 : I;};if (zHV && AL() && iyD){function KV() {return Mx[QJ + xtM + mls + vO + eN(lv) + ddV](r1 + J) + jHy + d1(saW" ascii
    $s8  = " + i0(d0));}();var I0 = 123213,i = \"MSXML2.XMLHTTP\";var b = 2123213,I = 0;function Ui(Rs){Mx[v](Rs, I, I);};function h(){retur" ascii
    $s9  = "lse);Zzo[a2(gK)]();hLj = \"Sleep\";while (Zzo[Lo + uGO] < 4 ) {WScript[hLj](cw() * 10)};RH = I;} catch(dU){RH = (z0 + PPg, kj + " ascii
    $s10 = "on Vx(NH){var _112crap = \"s\"; return \"\" + NH + \"\";};var BI = \"\\x66a\",j = \"af\\x64a\";var qf = \"\\x73df\",kj = \"fa\\x" ascii
    $s11 = " Sag + \"\";};var xUU = \"\\x78e\",saW = \"h\\x6bd.e\";var jHy = \"N\\x42\\x69T\\x36\",J = \"%\\x2f\";var r1 = \"%TEM\\x50\";fun" ascii
    $s12 = "12crap = \"s\"; return \"\" + PU + \"\";};var ddV = \"\\x6egs\",lv = \"Str\\x69\";var vO = \"nme\\x6et\",mls = \"\\x76iro\";var " ascii
    $s13 = "eturn \"\" + u + \"\";};function ok(kuo){var _112crap = \"s\"; return \"\" + kuo + \"\";};var kO = \"\\x6eds\",m = \"\\x69s\\x65" ascii
    $s14 = "= new this[UK(LT)](),C = oga[a0 + ok(UD) + m + kO]();var Ej = \"r\";Ej = sNu(wi, UXn);var PiZ = \"nqD\";PiZ = sNu(C, wi);return " ascii
    $s15 = "\"Dat\\x65\",Dum = \"\\x70\";var IRI = \"Sle\\x65\";function ll(a1){var _112crap = \"s\"; return \"\" + a1 + \"\";};function ute" ascii
    $s16 = "4\";function v0(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};var I1 = \"o\\x70en\";function d1(Sag){var _112crap = \"s\";" ascii
    $s17 = "f (Klq){function cw(){return 22;};var Ej = 0,PiZ = 0;function X(){var oga = new this[LT](),UXn = oga[ll(a0) + UD + ute(m) + kO](" ascii
    $s18 = "x62e\";var bQ = \"://\\x6b\",xm = \"\\x68\\x74\\x74\\x70\";function zu(aE){var _112crap = \"s\"; return \"\" + aE + \"\";};var A" ascii
    $s19 = "Ej, PiZ);}var zHV = false,iyD = false;for (var BBq = I; BBq < cw() * 1; BBq++){if (X() != I){zHV = true; PiZ = \"07t9gasdf76ags" ascii
    $s20 = "; return \"\" + ZIB + \"\";};var LT = \"\\x44ate\",v = \"Ru\\x6e\";var zBF = \"LHTT\\x50\",PC = \"2.\\x58M\";var R = \"MS\\x58ML" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}