rule sig_20160516_9b6326155eb710dc87af7fa0cce2ad36 {
  meta:
    description = "datamaliciousorder - file 20160516_9b6326155eb710dc87af7fa0cce2ad36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9a47e523ba89cdf3e0e00950775780e26438c4634bb70ffc1d1b1ae58f12004"

  strings:
    $s1  = "while (BjJX < vPvbRF - (9054 - 9052)) {" fullword ascii
    $s2  = "return cpOrtvV;" fullword ascii
    $s3  = "function rmUWs() {" fullword ascii
    $s4  = "function wabuyo() {" fullword ascii
    $s5  = "if (xdb === true) {" fullword ascii
    $s6  = "return BRoGF;" fullword ascii
    $s7  = "function IWmu() {" fullword ascii
    $s8  = "function Teg() {" fullword ascii
    $s9  = "return CQjFo;" fullword ascii
    $s10 = "return cuVJUmS;" fullword ascii
    $s11 = "function NCZV() {" fullword ascii
    $s12 = "function Hovodiq(eVBbC, BsJE) {" fullword ascii
    $s13 = "function YxnZ() {" fullword ascii
    $s14 = "return EmMC;" fullword ascii
    $s15 = "function IePB() {" fullword ascii
    $s16 = "function wqc(dfegg) {" fullword ascii
    $s17 = "return EihMh;" fullword ascii
    $s18 = "function vkvQr() {" fullword ascii
    $s19 = "function vtE() {" fullword ascii
    $s20 = "var OqVUMS = String;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}