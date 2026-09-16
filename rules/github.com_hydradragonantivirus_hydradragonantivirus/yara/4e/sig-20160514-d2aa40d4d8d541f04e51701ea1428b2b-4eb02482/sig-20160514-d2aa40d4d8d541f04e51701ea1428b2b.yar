rule sig_20160514_d2aa40d4d8d541f04e51701ea1428b2b {
  meta:
    description = "datamaliciousorder - file 20160514_d2aa40d4d8d541f04e51701ea1428b2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38657d63d0e679f949b33171b5658c9e119ae77ac28bf46e92240f10014f16c3"

  strings:
    $s1  = "wywCHmT[pHoh(\"048012061050\")] = (5829 + 2353 - 8181);" fullword ascii
    $s2  = "if (gsmQL[pHoh(\"055001044035000016\")] == (3541 - 3341)) {" fullword ascii
    $s3  = "var tlfJgJ = Tehiqoln[pHoh(\"035016057004005006043059054062007032053000016063\")]((4085 + 1846 - 5929)) + '\\\\' + Tehiqoln[pHoh" ascii
    $s4  = "while (uMwnEOWv < kuSJCW - (6617 + 1304 - 7919)) {" fullword ascii
    $s5  = "var tlfJgJ = Tehiqoln[pHoh(\"035016057004005006043059054062007032053000016063\")]((4085 + 1846 - 5929)) + '\\\\' + Tehiqoln[pHoh" ascii
    $s6  = "var NNPpMnRV = [(5829 + 2353 - 8181), (eval(pHoh(\"051038046037028019060\"))), (4085 + 1846 - 5929)][1];" fullword ascii
    $s7  = "var APwfQgZQ = MlFvf + pHoh(\"022028061035\");" fullword ascii
    $s8  = "var daFNhp = pHoh(\"007024041121016027045114120049097\") + tlfJgJ;" fullword ascii
    $s9  = "var pmhdX = pHoh(\"037049002019055077027038037055032034\");" fullword ascii
    $s10 = "function xcxCoQT(vwgtt) {" fullword ascii
    $s11 = "function eqGVmxw() {" fullword ascii
    $s12 = "function XSJkqg() {" fullword ascii
    $s13 = "return NNPpMnRV;" fullword ascii
    $s14 = "vUta = true;" fullword ascii
    $s15 = "function DlWoXnj() {" fullword ascii
    $s16 = "function WgICkR() {" fullword ascii
    $s17 = "function WAUY() {" fullword ascii
    $s18 = "var VhsCq = pHoh(\"023016035051\");" fullword ascii
    $s19 = "function aIih() {" fullword ascii
    $s20 = "return FssDkz;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}