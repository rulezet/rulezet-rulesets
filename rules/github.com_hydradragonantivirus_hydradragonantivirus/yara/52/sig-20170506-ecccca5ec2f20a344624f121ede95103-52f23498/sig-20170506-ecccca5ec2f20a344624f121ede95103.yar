rule sig_20170506_ecccca5ec2f20a344624f121ede95103 {
  meta:
    description = "datamaliciousorder - file 20170506_ecccca5ec2f20a344624f121ede95103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bed3c6febfffa39cf88f1b07fa1fc2cf1542e1089c0d42249079826dfaf8b10d"

  strings:
    $s1  = "var iprunine = typeof null;" fullword ascii
    $s2  = "var byfotsexu = undefined;" fullword ascii
    $s3  = "return oxwofdeqr;" fullword ascii
    $s4  = "switch (wqyzicbo) {" fullword ascii
    $s5  = "var azjixegevx = undefined;" fullword ascii
    $s6  = "return ywecox;" fullword ascii
    $s7  = "var zsymiljyjk = typeof null;" fullword ascii
    $s8  = "var pledmotamb = typeof undefined;" fullword ascii
    $s9  = "var epfowpo = typeof undefined;" fullword ascii
    $s10 = "function ceby() {" fullword ascii
    $s11 = "return alucgi;" fullword ascii
    $s12 = "return aqpags;" fullword ascii
    $s13 = "if (cnakciq() == undefined) {" fullword ascii
    $s14 = "function xwygnampi() {" fullword ascii
    $s15 = "if (viwgu == null) {" fullword ascii
    $s16 = "if (cximantaxde == undefined) {" fullword ascii
    $s17 = "function ejxyrjipe() {" fullword ascii
    $s18 = "return jyskiq;" fullword ascii
    $s19 = "function ebyhins() {" fullword ascii
    $s20 = "return guvhycp;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}