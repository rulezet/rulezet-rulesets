rule sig_20160514_78fc447ffafafe5bfad554f364d8a591 {
  meta:
    description = "datamaliciousorder - file 20160514_78fc447ffafafe5bfad554f364d8a591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce9584669d69969bed38595c9e387be5e43fe7d2a7cd049d49bbef9f1442ec1"

  strings:
    $s1  = "while (yCZzwrE < IGsOfXcV - (7009 + 1958 - 8965)) {" fullword ascii
    $s2  = "function uvZHBu(dSvsvq, qPbL) {" fullword ascii
    $s3  = "return bIfufy;" fullword ascii
    $s4  = "function aPW() {" fullword ascii
    $s5  = "return adLnm;" fullword ascii
    $s6  = "return kLbFCvRh;" fullword ascii
    $s7  = "return tXPCqdU;" fullword ascii
    $s8  = "return FFrX;" fullword ascii
    $s9  = "function cfhxTij() {" fullword ascii
    $s10 = "function bFlyEPR(oUSEKT) {" fullword ascii
    $s11 = "function gGop() {" fullword ascii
    $s12 = "function fwqrqE() {" fullword ascii
    $s13 = "function UHQc(trwd, kXQ) {" fullword ascii
    $s14 = "function IyxZFru(SpDUV) {" fullword ascii
    $s15 = "function FWZXl() {" fullword ascii
    $s16 = "function LMJPC() {" fullword ascii
    $s17 = "function nguu(oPV, DHn) {" fullword ascii
    $s18 = "return VgwW;" fullword ascii
    $s19 = "return JmKyYIX;" fullword ascii
    $s20 = "return EjPjgq;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}