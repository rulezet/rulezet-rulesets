rule sig_20160514_0ad0c88d90573a487bdc54235625cf44 {
  meta:
    description = "datamaliciousorder - file 20160514_0ad0c88d90573a487bdc54235625cf44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6079a0fd2fed6441853852d48ed01a9d7116aae72552cb9f57726d08382a07d"

  strings:
    $s1  = "while (lMPHOxaN < jIST - (8032 - 8030)) {" fullword ascii
    $s2  = "return BPTeH;" fullword ascii
    $s3  = "return vqrjVv;" fullword ascii
    $s4  = "function YYvtRbK(jJi) {" fullword ascii
    $s5  = "if (TMNqojA == false) {" fullword ascii
    $s6  = "return FzjE;" fullword ascii
    $s7  = "function kzzE(yhnFq, NTfcePvp) {" fullword ascii
    $s8  = "function aTek() {" fullword ascii
    $s9  = "function fCN() {" fullword ascii
    $s10 = "return ffmwOd;" fullword ascii
    $s11 = "lTeSku = true;" fullword ascii
    $s12 = "if (YUmrGUk(\"SsoFgjW\", 0) == true) {" fullword ascii
    $s13 = "function eYmnqRa() {" fullword ascii
    $s14 = "return SWilAQgU;" fullword ascii
    $s15 = "return gVajj[jJi];" fullword ascii
    $s16 = "function QqIRDLS() {" fullword ascii
    $s17 = "return TtVw;" fullword ascii
    $s18 = "function fKx() {" fullword ascii
    $s19 = "function zzWXRRB() {" fullword ascii
    $s20 = "return bZjzrg;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}