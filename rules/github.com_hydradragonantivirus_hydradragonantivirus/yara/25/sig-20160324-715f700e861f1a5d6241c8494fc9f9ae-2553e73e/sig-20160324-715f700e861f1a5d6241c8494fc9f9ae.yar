rule sig_20160324_715f700e861f1a5d6241c8494fc9f9ae {
  meta:
    description = "datamaliciousorder - file 20160324_715f700e861f1a5d6241c8494fc9f9ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02af1afb57b75aa34e003e4ec713f8be2eb8ad74c81a836427e19127c450b417"

  strings:
    $s1  = "var tgm = \"\\x65\",hs = \"clo\\x73\";var HG = \"oFi\\x6ce\",FH = \"\\x53\\x61veT\";var WH = \"t\\x69\\x6fn\",KDI = \"p\\x6fsi\"" ascii
    $s2  = "4, 5, ja); return eR;};E = WScript[xKn()](c0 + Qc + GOG);oc = E;oc[(Wwb(N))]();oc[wG(VRU)] = h(1);oc[UfU](G[sG + Zal + St]);oc[K" ascii
    $s3  = "var Rtf = false,SM = \"CreateObject\";var i = function p() {return WScript[SM](ZQu + i0 + Zzl(Cf));}();var d = 123213,uR = \"MSX" ascii
    $s4  = "r w = 0,h0 = 0;function Xi(){var zKd = new this[zW](),px = zKd[Tz + cnT + g + kL]();WScript[O0](qRK());var zKd = new this[zW]()," ascii
    $s5  = "qt = zKd[Tz + cnT + s0(g) + yy(kL)]();WScript[O0](qRK());var zKd = new this[xNi(zW)](),p1 = zKd[i1(Tz) + cnT + O(g) + kL]();var " ascii
    $s6  = "* 1; hSk++){if (Xi() != lXw){SX = true; h0 = \"07t9gasdf76ags\" + 123313 * w + h0; vAF = true; h0 = \"07t9gasdf76ags\" + 123313 " ascii
    $s7  = " \"read\\x79\";var AH = \"\\x53l\\x65ep\",a = \"s\\x65n\\x64\";function o(Il){var _112crap = \"s\"; return \"\" + Il + \"\";};va" ascii
    $s8  = "+ h0; break;}}function b() {return ((SX == true) && (SX == vAF)) ? 1 : lXw;};if (SX && b() && vAF){function HBG() {return i[nn(P" ascii
    $s9  = ".XMLHTTP\";var X = 2123213,lXw = 0;function APZ(YF){i[pEt](YF, lXw, lXw);};function jBS(){return uR;};function m(I, s){return I " ascii
    $s10 = "< 4 ) {WScript[JtQ](qRK() * 10)};yMf = lXw;} catch(DH){yMf = (MA, pMk + xj, oZS + yee, 2);};}function h(ja) {var eR = (1, 2, 3, " ascii
    $s11 = "\\x6e\";function SO(tlM){var _112crap = \"s\"; return \"\" + tlM + \"\";};var c = \"\\x65\",F = \"5\\x58.ex\";var b0 = \"Z1A\\x3" ascii
    $s12 = "\\x64f\";var pMk = \"f\\x61df\",MA = \"a\\x73dfa\";function H0(U0){var _112crap = \"s\"; return \"\" + U0 + \"\";};var y = \"s" ascii
    $s13 = "return \"\" + Q + \"\";};function O2(Pw){var _112crap = \"s\"; return \"\" + Pw + \"\";};var idI = \"\\x6egs\",D = \"\\x53tri\";" ascii
    $s14 = "var _112crap = \"s\"; return \"\" + A + \"\";};function yy(C){var _112crap = \"s\"; return \"\" + C + \"\";};function i1(r){var " ascii
    $s15 = " = \"\\x54CMil\",Tz = \"\\x67\\x65\\x74\\x55\";function xNi(fY){var _112crap = \"s\"; return \"\" + fY + \"\";};var zW = \"\\x44" ascii
    $s16 = "x64J\";function p2(gn){var _112crap = \"s\"; return \"\" + gn + \"\";};var Ir = \"%\\x2f\",LR = \"\\x25T\\x45M\\x50\";function n" ascii
    $s17 = ";var U = \"\\x3a//\\x77\",Cc = \"\\x68ttp\";var ARV = \"\\x47ET\";function Wwb(Z){var _112crap = \"s\"; return \"\" + Z + \"\";}" ascii
    $s18 = "s\"; return \"\" + r + \"\";};function O(FoW){var _112crap = \"s\"; return \"\" + FoW + \"\";};var kL = \"\\x63ond\\x73\",g = \"" ascii
    $s19 = "while (yMf){try {G[N](ARV, o(Cc) + U + H + sB + Hd + OWS + G0 + TZ + fG + A0, false);G[a]();JtQ = \"Sleep\";while (G[H0(ARI) + y" ascii
    $s20 = "9\",Zal = \"o\\x6es\\x65\";var sG = \"R\\x65sp\",UfU = \"wri\\x74e\";function wG(esA){var _112crap = \"s\"; return \"\" + esA + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}