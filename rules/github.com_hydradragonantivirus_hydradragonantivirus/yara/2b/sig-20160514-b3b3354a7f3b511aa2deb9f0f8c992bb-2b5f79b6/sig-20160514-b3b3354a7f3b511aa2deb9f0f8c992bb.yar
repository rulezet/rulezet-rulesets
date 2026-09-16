rule sig_20160514_b3b3354a7f3b511aa2deb9f0f8c992bb {
  meta:
    description = "datamaliciousorder - file 20160514_b3b3354a7f3b511aa2deb9f0f8c992bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03a35139aa5e596c7b651ee9e08c9cc13974fd2e4d634bd5aebc54ed072de47a"

  strings:
    $s1  = "var bunk = kJjg + (3254 + 1488 - 4740);" fullword ascii
    $s2  = "while (kJjg < BfmJMA - (3254 + 1488 - 4740)) {" fullword ascii
    $s3  = "function RxTN(uzeRDpPv, loGaxd) {" fullword ascii
    $s4  = "return xZhfwK;" fullword ascii
    $s5  = "var MZAsTs = true;" fullword ascii
    $s6  = "var gLCu = false;" fullword ascii
    $s7  = "return UqmE;" fullword ascii
    $s8  = "return bKvr;" fullword ascii
    $s9  = "return BTxS;" fullword ascii
    $s10 = "function zFPy(ghF) {" fullword ascii
    $s11 = "return tPbLby;" fullword ascii
    $s12 = "function oDOCWt() {" fullword ascii
    $s13 = "function jtI() {" fullword ascii
    $s14 = "return xhgom;" fullword ascii
    $s15 = "return qDjsp;" fullword ascii
    $s16 = "function aMRp() {" fullword ascii
    $s17 = "if (DxEw === false) {" fullword ascii
    $s18 = "var aQbxm = false;" fullword ascii
    $s19 = "return rmHB;" fullword ascii
    $s20 = "function KXEn() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}