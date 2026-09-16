rule sig_20160516_cfbe683f481239e2b4edf0dd65202855 {
  meta:
    description = "datamaliciousorder - file 20160516_cfbe683f481239e2b4edf0dd65202855.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c122a9a8aa3363e146d674893df11a9f1f8a5b6b065ce237dc4a189bf035883"

  strings:
    $s1  = "while (Zvey < mcTayTG - (888 - 886)) {" fullword ascii
    $s2  = "return vsLngHZE;" fullword ascii
    $s3  = "return xElafRj;" fullword ascii
    $s4  = "return oqLDFTS;" fullword ascii
    $s5  = "return nSQIg;" fullword ascii
    $s6  = "function roBcQOM(uOnO) {" fullword ascii
    $s7  = "function LBa(dfegg) {" fullword ascii
    $s8  = "function BCEmL() {" fullword ascii
    $s9  = "return rrhsWaR;" fullword ascii
    $s10 = "if (lRLTZB === false) {" fullword ascii
    $s11 = "function CKBn() {" fullword ascii
    $s12 = "function otx() {" fullword ascii
    $s13 = "return sZvn;" fullword ascii
    $s14 = "return lEqcO;" fullword ascii
    $s15 = "return nkBAiQCj;" fullword ascii
    $s16 = "function dxC(myJN) {" fullword ascii
    $s17 = "function Ewz() {" fullword ascii
    $s18 = "function SZyNU() {" fullword ascii
    $s19 = "return hONJr;" fullword ascii
    $s20 = "return XOMn;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}