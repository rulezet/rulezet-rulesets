rule sig_20160513_e1061591ef35f69de67d1f1389852323 {
  meta:
    description = "datamaliciousorder - file 20160513_e1061591ef35f69de67d1f1389852323.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b52ae82cc0e3c3a3635c6c7c82473f10e64c06989f60f1e0634c5afecbc0e76"

  strings:
    $s1  = "while (yEaG < CNRcFxfC - (6985 + 1460 - 8443)) {" fullword ascii
    $s2  = "function aeyN(lULDLP, yDyiJH) {" fullword ascii
    $s3  = "function WnRMHsW(dfegg) {" fullword ascii
    $s4  = "function zejXxqW() {" fullword ascii
    $s5  = "function xJmi() {" fullword ascii
    $s6  = "function ptMFsb() {" fullword ascii
    $s7  = "return wUidx;" fullword ascii
    $s8  = "return fLpcysfx;" fullword ascii
    $s9  = "return tEEczEv;" fullword ascii
    $s10 = "function smPpJg() {" fullword ascii
    $s11 = "function bagSY(tuiyo, fmmd, kemn) {" fullword ascii
    $s12 = "function dotSNO() {" fullword ascii
    $s13 = "function UPnkz(LaFsMWWr, mMmqUT) {" fullword ascii
    $s14 = "function gDoWPO() {" fullword ascii
    $s15 = "return iCWlWogU;" fullword ascii
    $s16 = "var QJpMr = false;" fullword ascii
    $s17 = "var nXXNQG = false;" fullword ascii
    $s18 = "return mOyA;" fullword ascii
    $s19 = "unXgqZ = true;" fullword ascii
    $s20 = "return gesYo;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}