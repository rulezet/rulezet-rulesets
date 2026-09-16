rule sig_20170123_c498cb13cc8f20e52c99f5d83803537b {
  meta:
    description = "datamaliciousorder - file 20170123_c498cb13cc8f20e52c99f5d83803537b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e23df677a570fb87e86a39a1b5c9a5744aef0983cde2dc45ccbea1b2861a764"

  strings:
    $x1  = "var gnebexti = \"cmd.exe /c \" + wwebi + \"  $khesi='^e Proces';$nmohun='^gi.exe'')';$umojqa='^=($env:t';$noly='^icy Bypa';$gozf" ascii
    $s2  = "var ilanento = true;" fullword ascii
    $s3  = "return xuhgalwyma;" fullword ascii
    $s4  = "function gazozi() {" fullword ascii
    $s5  = "var clovno = undefined;" fullword ascii
    $s6  = "var ictila = null;" fullword ascii
    $s7  = "return gaxsaqfy;" fullword ascii
    $s8  = "function akiky() {" fullword ascii
    $s9  = "var obbylla = null;" fullword ascii
    $s10 = "return 114.3;" fullword ascii
    $s11 = "return citufujl;" fullword ascii
    $s12 = "var citufujl = undefined;" fullword ascii
    $s13 = "var txulosohk = undefined;" fullword ascii
    $s14 = "function ywidcyqbysz() {" fullword ascii
    $s15 = "if (ogan() == undefined) {" fullword ascii
    $s16 = "if (jylebopdy === null) {" fullword ascii
    $s17 = "function xcuxamz() {" fullword ascii
    $s18 = "function nquhyjub() {" fullword ascii
    $s19 = "if (ihuniz() === null) {" fullword ascii
    $s20 = "function ebbeqlepke() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}