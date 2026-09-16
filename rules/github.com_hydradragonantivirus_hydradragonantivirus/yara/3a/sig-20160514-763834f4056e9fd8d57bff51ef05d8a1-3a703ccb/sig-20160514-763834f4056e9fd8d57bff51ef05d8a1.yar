rule sig_20160514_763834f4056e9fd8d57bff51ef05d8a1 {
  meta:
    description = "datamaliciousorder - file 20160514_763834f4056e9fd8d57bff51ef05d8a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "089ef6035a1f5e8ac7d9becf96cf03e8a821dfce7998d683ec4eba2945794d66"

  strings:
    $s1  = "while (hQRu < uazUy - (4242 + 1248 - 5488)) {" fullword ascii
    $s2  = "var oVun = true;" fullword ascii
    $s3  = "return kmTHB;" fullword ascii
    $s4  = "return WkUv;" fullword ascii
    $s5  = "function LzeZTVr() {" fullword ascii
    $s6  = "return JGPbLHRn;" fullword ascii
    $s7  = "return mYWZTsE;" fullword ascii
    $s8  = "return rsYq;" fullword ascii
    $s9  = "function gNuM() {" fullword ascii
    $s10 = "function oxBxObx() {" fullword ascii
    $s11 = "function eeKHqm() {" fullword ascii
    $s12 = "return wbFZ;" fullword ascii
    $s13 = "return HPnv;" fullword ascii
    $s14 = "if (nBvH === true) {" fullword ascii
    $s15 = "function xsg(ZKLlJk) {" fullword ascii
    $s16 = "return luJmgqeu;" fullword ascii
    $s17 = "return SOqSGI;" fullword ascii
    $s18 = "function orzfF(yJnKty, hKtQGPZV) {" fullword ascii
    $s19 = "if (mnBCpZ(false, true) == 0) {" fullword ascii
    $s20 = "function uNMA() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}