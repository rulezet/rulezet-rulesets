rule sig_20160513_cfc0639c04a178adb992633b3f49302a {
  meta:
    description = "datamaliciousorder - file 20160513_cfc0639c04a178adb992633b3f49302a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aca72152927005aea81140a64674ea32fdd073d1073b2b49b70d84958aa95a74"

  strings:
    $s1  = "var roTO = (8332 - 8332);" fullword ascii
    $s2  = "while (boAUJx < NBuNu - (8714 + 2203 - 10915)) {" fullword ascii
    $s3  = "roTO = IaM('' + HRwZg + '');" fullword ascii
    $s4  = "fSvXyYu = fSvXyYu + rvOG[GdpcYq](roTO);" fullword ascii
    $s5  = "function yaYMF(tuiyo, fmmd, kemn) {" fullword ascii
    $s6  = "function IaM(cXQPkRZ) {" fullword ascii
    $s7  = "return jRRhpOnI;" fullword ascii
    $s8  = "return fSvXyYu;" fullword ascii
    $s9  = "return xglkxlG;" fullword ascii
    $s10 = "function WCUf() {" fullword ascii
    $s11 = "function kpyQ() {" fullword ascii
    $s12 = "function XIxf(Sxvml) {" fullword ascii
    $s13 = "roTO = fhXtE(roTO, QVxLpvTJ);" fullword ascii
    $s14 = "if (kpyQ(false) == 0) {" fullword ascii
    $s15 = "function soo() {" fullword ascii
    $s16 = "function JeSWR(YsoMwH, DXKy) {" fullword ascii
    $s17 = "function WRycFFA() {" fullword ascii
    $s18 = "znZix = true;" fullword ascii
    $s19 = "return xMkVNjH;" fullword ascii
    $s20 = "function BjUz() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}