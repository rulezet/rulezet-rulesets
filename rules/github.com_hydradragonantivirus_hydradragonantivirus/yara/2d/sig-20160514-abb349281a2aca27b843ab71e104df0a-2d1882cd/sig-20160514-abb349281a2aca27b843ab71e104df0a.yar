rule sig_20160514_abb349281a2aca27b843ab71e104df0a {
  meta:
    description = "datamaliciousorder - file 20160514_abb349281a2aca27b843ab71e104df0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "658b5e110cc491e514b5d307414f3a00ada6e7973dd22cb1986b8fa99520a499"

  strings:
    $s1  = "while (iXfB < zsLUny - (565 - 563)) {" fullword ascii
    $s2  = "return ZHlu;" fullword ascii
    $s3  = "var JRsbLA = false;" fullword ascii
    $s4  = "function hoiKwbi() {" fullword ascii
    $s5  = "function DtpK() {" fullword ascii
    $s6  = "function kIlnP(NyOXew, rwaB) {" fullword ascii
    $s7  = "return axAim;" fullword ascii
    $s8  = "return iPKhRZU;" fullword ascii
    $s9  = "function uLFRbPc() {" fullword ascii
    $s10 = "return LkNDvd;" fullword ascii
    $s11 = "function VXf() {" fullword ascii
    $s12 = "return CkGsOqN;" fullword ascii
    $s13 = "function jVzxtwM(ZbbEFoBs, ikGHsn) {" fullword ascii
    $s14 = "return yTcYcp;" fullword ascii
    $s15 = "switch (\"KiwZkUDt\") {" fullword ascii
    $s16 = "return UJzGUmjp;" fullword ascii
    $s17 = "return JDPx;" fullword ascii
    $s18 = "return nGYrlWfX;" fullword ascii
    $s19 = "return uRcvAef;" fullword ascii
    $s20 = "var hViRXQk = String;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}