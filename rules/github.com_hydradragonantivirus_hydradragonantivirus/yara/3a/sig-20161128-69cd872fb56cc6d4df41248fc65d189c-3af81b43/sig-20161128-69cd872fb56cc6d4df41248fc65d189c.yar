rule sig_20161128_69cd872fb56cc6d4df41248fc65d189c {
  meta:
    description = "datamaliciousorder - file 20161128_69cd872fb56cc6d4df41248fc65d189c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9543c3831f221ee5a8bd5f59b357b2fb4dfed98d7b955c222b3a0047da0b802a"

  strings:
    $s1  = "return new Function(ikwepa + dcube + \"object')[uzibdocx]('C:\\\\\\\\')['type']['length'] > 1\");" fullword ascii
    $s2  = "var dcube = \"Object('scripting.fileSystem\";" fullword ascii
    $s3  = "return '35003';" fullword ascii
    $s4  = "return wkofguzpehb;" fullword ascii
    $s5  = "if (pguxnunradu() === undefined) {" fullword ascii
    $s6  = "var ppixsygwajs = null;" fullword ascii
    $s7  = "var kofev = undefined;" fullword ascii
    $s8  = "var urofleh = undefined;" fullword ascii
    $s9  = "function uscibas() {" fullword ascii
    $s10 = "var fawaja = false;" fullword ascii
    $s11 = "function yshuwa() {" fullword ascii
    $s12 = "function adcybdu() {" fullword ascii
    $s13 = "function oxunpi() {" fullword ascii
    $s14 = "var vqufvi = undefined;" fullword ascii
    $s15 = "function qegrudp() {" fullword ascii
    $s16 = "var eqotzyfyk = undefined;" fullword ascii
    $s17 = "return \"45767\";" fullword ascii
    $s18 = "if (ygliqind() == null) {" fullword ascii
    $s19 = "function ymubulg() {" fullword ascii
    $s20 = "if (uscibas() == undefined) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}