rule sig_20160427_31c83ca4c79d439dd5c51f1f655ae492 {
  meta:
    description = "datamaliciousorder - file 20160427_31c83ca4c79d439dd5c51f1f655ae492.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f0ee9ea711b32e45718ed79263621f27484a2977cbb9b942af5d9352d37c16"

  strings:
    $s1  = " if(5 === true) {" fullword ascii
    $s2  = "switch(3) {" fullword ascii
    $s3  = "  var nOuV = false; " fullword ascii
    $s4  = " var rGMgPz = true; " fullword ascii
    $s5  = "  var KGQ = false; " fullword ascii
    $s6  = "function gMJBr (LXNeq,Lrjp) {" fullword ascii
    $s7  = "}switch(203) {" fullword ascii
    $s8  = "function ziCLmj (MMDlgM) {" fullword ascii
    $s9  = " var zlCp = false; " fullword ascii
    $s10 = "}function DKuAG (Esv) {" fullword ascii
    $s11 = "switch(false) {" fullword ascii
    $s12 = "function oJxYqIv () {" fullword ascii
    $s13 = "function tKf () {" fullword ascii
    $s14 = "function VzWl () {" fullword ascii
    $s15 = "}}function oeDmzN (kPMXy) {" fullword ascii
    $s16 = " if(YpL == true) {" fullword ascii
    $s17 = " if(ZkLckc == true) {" fullword ascii
    $s18 = " var OFsQ = false; " fullword ascii
    $s19 = " var oXpuk = true; " fullword ascii
    $s20 = "function tqXBS () {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}