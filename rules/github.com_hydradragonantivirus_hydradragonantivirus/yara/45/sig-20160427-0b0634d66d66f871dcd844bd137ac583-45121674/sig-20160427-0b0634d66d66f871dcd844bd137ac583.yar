rule sig_20160427_0b0634d66d66f871dcd844bd137ac583 {
  meta:
    description = "datamaliciousorder - file 20160427_0b0634d66d66f871dcd844bd137ac583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e93df94bcc6b1278920b235ef429f3bde4740f64fcfbd8e3e56352f34452cb2"

  strings:
    $s1  = "}switch(false) {" fullword ascii
    $s2  = "function sIvu () {" fullword ascii
    $s3  = "function zKjJ (Xee) {" fullword ascii
    $s4  = "function oops (FJkLeBs,QGfdyZN) {" fullword ascii
    $s5  = " var BbS = false; " fullword ascii
    $s6  = " var NDM = false; " fullword ascii
    $s7  = " if(MpZz == false) {" fullword ascii
    $s8  = "function EjBlVG ( dldd , lfdff) {" fullword ascii
    $s9  = "switch(768) {" fullword ascii
    $s10 = "} var oAML = false; " fullword ascii
    $s11 = "switch(3) {" fullword ascii
    $s12 = " var gmiObqO = true; " fullword ascii
    $s13 = "function TRti () {" fullword ascii
    $s14 = " if(1 === true) {" fullword ascii
    $s15 = " if(7 == true) {" fullword ascii
    $s16 = " var Ybse = false; " fullword ascii
    $s17 = " if(dEAb == false) {" fullword ascii
    $s18 = "case \"rYGnSAM\":" fullword ascii
    $s19 = " var zaTEXp = true; " fullword ascii
    $s20 = "function AIZf (xnEpBcw) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}