rule sig_20161010_61eb8d346576d49bf050f2ab2e2c26fb {
  meta:
    description = "datamaliciousorder - file 20161010_61eb8d346576d49bf050f2ab2e2c26fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e3cbc7b4f1bac2bd68c74fc479c7907a8ec689693e5c456bab95341190caf4b"

  strings:
    $x1  = "coqy.run(\"CmD.Exe /c poWERS^H^eLL^.ExE   ^-exe^C^uTI^O^NP^o^LIc^y ^By^pa^S^s  -^n^oPrOF^iL^E   -^wIn^dowSTY^Le^   ^hi^Dde^N   (" ascii
    $s2  = "data%.eXE'\", false);" fullword ascii
    $s3  = "return \"ofile.dou\";" fullword ascii
    $s4  = "function ovnircaxgy() {" fullword ascii
    $s5  = "if (typeof document == 'undefined') {" fullword ascii
    $s6  = "function boxepu() {" fullword ascii
    $s7  = "function silmyk() {" fullword ascii
    $s8  = "var intehekni = null;" fullword ascii
    $s9  = "switch (yqlehp()) {" fullword ascii
    $s10 = "function oxuduw() {" fullword ascii
    $s11 = "var vnippagmimy = undefined;" fullword ascii
    $s12 = "if (tozirnyxa === null) {" fullword ascii
    $s13 = "var uqmacu = typeof undefined;" fullword ascii
    $s14 = "return \"bledating\";" fullword ascii
    $s15 = "function dgido() {" fullword ascii
    $s16 = "return akdaby;" fullword ascii
    $s17 = "return 805;" fullword ascii
    $s18 = "var awashutw = undefined;" fullword ascii
    $s19 = "var codunc = null;" fullword ascii
    $s20 = "var tozirnyxa = null;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}