rule sig_20160427_fafb9ae630c6e04eb1c988b4abc2e34b {
  meta:
    description = "datamaliciousorder - file 20160427_fafb9ae630c6e04eb1c988b4abc2e34b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "459f5c1cf455923a4a68332b306a9d81362438c05cae3b88735c22840ff14e00"

  strings:
    $s1  = "}switch(7) {" fullword ascii
    $s2  = "switch(0) {" fullword ascii
    $s3  = "}switch(false) {" fullword ascii
    $s4  = " if(1 === true) {" fullword ascii
    $s5  = "switch(4) {" fullword ascii
    $s6  = "switch(false) {" fullword ascii
    $s7  = "} if(1 === true) {" fullword ascii
    $s8  = " if(4 == true) {" fullword ascii
    $s9  = "}switch(3) {" fullword ascii
    $s10 = "}switch(2) {" fullword ascii
    $s11 = "} if(3 == true) {" fullword ascii
    $s12 = " if(6 === true) {" fullword ascii
    $s13 = " var wgkXz = false; " fullword ascii
    $s14 = "function vdznAOy ( dldd , lfdff) {" fullword ascii
    $s15 = " var JKkQN = true; " fullword ascii
    $s16 = "alse;  } } }else{ if(qReQV(331,1) == true) { function dfglflf () {" fullword ascii
    $s17 = "  var Ckrd = true; " fullword ascii
    $s18 = " var lLGCc = true; " fullword ascii
    $s19 = " var RYtH = true; " fullword ascii
    $s20 = "}return false;}function RwplBq () {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}