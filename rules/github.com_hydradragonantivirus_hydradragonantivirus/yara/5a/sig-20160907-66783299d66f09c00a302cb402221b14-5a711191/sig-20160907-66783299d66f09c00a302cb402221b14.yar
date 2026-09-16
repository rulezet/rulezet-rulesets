rule sig_20160907_66783299d66f09c00a302cb402221b14 {
  meta:
    description = "datamaliciousorder - file 20160907_66783299d66f09c00a302cb402221b14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3264503cc2f043d66b791f673544aff2a0b0e9f3f6de651609e9d64c228b4256"

  strings:
    $s1  = "function jjovjebwe2() {" fullword ascii
    $s2  = "return waglexy4;" fullword ascii
    $s3  = "function mkinkexawqo0() {" fullword ascii
    $s4  = "return prezi0;" fullword ascii
    $s5  = "function nzujhyly3() {" fullword ascii
    $s6  = "function ogicwad4() {" fullword ascii
    $s7  = "return ylmeskefv0;" fullword ascii
    $s8  = "return owvopfysly3;" fullword ascii
    $s9  = "function yjkagcuzcybr0() {" fullword ascii
    $s10 = "return mkoreqi4;" fullword ascii
    $s11 = "function epxydk9() {" fullword ascii
    $s12 = "return zpohifpizs6;" fullword ascii
    $s13 = "function aducymru7() {" fullword ascii
    $s14 = "return alfos1;" fullword ascii
    $s15 = "function ydhyzo6() {" fullword ascii
    $s16 = "function ihumozh9() {" fullword ascii
    $s17 = "function ybsoszy6() {" fullword ascii
    $s18 = "function ynom9() {" fullword ascii
    $s19 = "return miqi5;" fullword ascii
    $s20 = "function yhatjyguhb6() {" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}