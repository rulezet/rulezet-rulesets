rule sig_20160427_da84d55c6e292a4548d91a7abe30488f {
  meta:
    description = "datamaliciousorder - file 20160427_da84d55c6e292a4548d91a7abe30488f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a11103de01cd0a430a7a5cb31c99722748dc347b29aaa971813dadd971d4b75"

  strings:
    $s1  = " if(1 == true) {" fullword ascii
    $s2  = " if(5 == false) {" fullword ascii
    $s3  = "}switch(false) {" fullword ascii
    $s4  = " if(3 === false) {" fullword ascii
    $s5  = " if(7 == false) {" fullword ascii
    $s6  = "switch(false) {" fullword ascii
    $s7  = "}switch(0) {" fullword ascii
    $s8  = "}switch(5) {" fullword ascii
    $s9  = "switch(5) {" fullword ascii
    $s10 = "} var UEl = false; " fullword ascii
    $s11 = "  var RwK = false; " fullword ascii
    $s12 = " var KfH = false; " fullword ascii
    $s13 = "function WiiTQIx ( dldd , lfdff) {" fullword ascii
    $s14 = " var cZiKRX = true; " fullword ascii
    $s15 = " var Gdt = false; " fullword ascii
    $s16 = "function MgaD () {" fullword ascii
    $s17 = " if(GoiQdWm == true) {" fullword ascii
    $s18 = "switch(aZCft) {" fullword ascii
    $s19 = " var NxMeftk = false; " fullword ascii
    $s20 = "function shvcM () {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}