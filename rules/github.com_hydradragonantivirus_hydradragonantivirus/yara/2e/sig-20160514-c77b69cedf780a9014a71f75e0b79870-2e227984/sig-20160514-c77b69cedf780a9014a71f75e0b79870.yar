rule sig_20160514_c77b69cedf780a9014a71f75e0b79870 {
  meta:
    description = "datamaliciousorder - file 20160514_c77b69cedf780a9014a71f75e0b79870.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cee99d9c399c49475485f497c3d6f56811d58fa318016d49d61feeea1b0c7b4"

  strings:
    $s1  = "roUb[KBHTBf(\"002010019052\")] = (1510 - 1509);" fullword ascii
    $s2  = "while (IjvtBrF < mvyJ - (6401 - 6399)) {" fullword ascii
    $s3  = "function SVm() {" fullword ascii
    $s4  = "return lxafMH;" fullword ascii
    $s5  = "return wMKrWlW;" fullword ascii
    $s6  = "function tRIYYg(ItoxdlhG) {" fullword ascii
    $s7  = "return ThLlZIC;" fullword ascii
    $s8  = "function WKAhIH() {" fullword ascii
    $s9  = "function kmkQS() {" fullword ascii
    $s10 = "return zRfIZtE;" fullword ascii
    $s11 = "function dFXr() {" fullword ascii
    $s12 = "function gKS() {" fullword ascii
    $s13 = "function KEiuW(gVEgDOUo, yDFxJBS) {" fullword ascii
    $s14 = "function KBHTBf(KJyHaQqu) {" fullword ascii
    $s15 = "return KVVRsPgA;" fullword ascii
    $s16 = "return uFGu;" fullword ascii
    $s17 = "function cYMHS() {" fullword ascii
    $s18 = "function UOFG() {" fullword ascii
    $s19 = "return LXGjek;" fullword ascii
    $s20 = "function rsqwyb() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}