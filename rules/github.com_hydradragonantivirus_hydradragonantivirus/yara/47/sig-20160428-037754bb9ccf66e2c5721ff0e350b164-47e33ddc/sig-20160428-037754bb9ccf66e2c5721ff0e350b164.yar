rule sig_20160428_037754bb9ccf66e2c5721ff0e350b164 {
  meta:
    description = "datamaliciousorder - file 20160428_037754bb9ccf66e2c5721ff0e350b164.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62862c9e274e8a916892cc8563b11440e23d86bfe7ea187ee210b39d6d90002e"

  strings:
    $s1  = "while (wKzCYYf < rEaGrvR - (2896, 7018, 8774, 230, 1262, 821, 5801, 1227, 7776, 2)) {" fullword ascii
    $s2  = "return ZATBA + HbJoYUY + HmxaGIMw + nQQ + RyU + xvfY;" fullword ascii
    $s3  = "if (3 == false) {" fullword ascii
    $s4  = "if (2 === true) {" fullword ascii
    $s5  = "if (6 == true) {" fullword ascii
    $s6  = "if (6 == false) {" fullword ascii
    $s7  = "var JJCVkx = true;" fullword ascii
    $s8  = "var DfJzuWu = true;;" fullword ascii
    $s9  = "return yqGRXu;" fullword ascii
    $s10 = "var aSygDC = true;" fullword ascii
    $s11 = "function VNLs(dfegg) {" fullword ascii
    $s12 = "return AVH;" fullword ascii
    $s13 = "var NUkSTD = true;" fullword ascii
    $s14 = "return JcroNv;" fullword ascii
    $s15 = "var PWMWcZ = [egreNaRj, eaQ, Rodd, yiKubrr, mmbghf, ykaz, kAf, qocF, gsRpd, ruCV];" fullword ascii
    $s16 = "var OSLRGVS = true;" fullword ascii
    $s17 = "var jsSxd = false;" fullword ascii
    $s18 = "if (7 === true) {" fullword ascii
    $s19 = "function HDJYbO(FnpcJz) {" fullword ascii
    $s20 = "var mRUvoJ = false;;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}