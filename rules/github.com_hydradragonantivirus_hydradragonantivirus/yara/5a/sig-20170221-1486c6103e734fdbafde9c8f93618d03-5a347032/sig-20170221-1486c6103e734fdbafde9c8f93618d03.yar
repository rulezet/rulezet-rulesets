rule sig_20170221_1486c6103e734fdbafde9c8f93618d03 {
  meta:
    description = "datamaliciousorder - file 20170221_1486c6103e734fdbafde9c8f93618d03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a6008c47a73007d4df74b5dcebdce382f512cd2bddc8c18ce220e21d66ba97"

  strings:
    $s1  = "return [new String(\"dveld\"), new String(\"u\"), new String(\"xo\"), new String(\"muv\"), new String(\"ekd\"), new String(\"ulq" ascii
    $s2  = "ring(\"act\"), new String(\"apbi\"), \"env:\", new String(\"dimq\")][8];" fullword ascii
    $s3  = "return [new String(\"i\"), new String(\"nacq\"), \"cmd.\", new String(\"h\"), new String(\"ugwo\"), new String(\"ady\"), new Str" ascii
    $s4  = "return [new String(\"j\"), new String(\"uzt\"), new String(\"yxj\"), new String(\"spyrb\"), new String(\"fon\"), new String(\"y" ascii
    $s5  = "return [new String(\"i\"), new String(\"nacq\"), \"cmd.\", new String(\"h\"), new String(\"ugwo\"), new String(\"ady\"), new Str" ascii
    $s6  = "return [new String(\"j\"), new String(\"uzt\"), new String(\"yxj\"), new String(\"spyrb\"), new String(\"fon\"), new String(\"y" ascii
    $s7  = "oqomfukdygr[itvuxumv]([new String(\"bfo\"), new String(\"umg\"), udyjlavh() + gkagu() + npihnizy() + fushepy() + xobcy() + etefr" ascii
    $s8  = " + pedelm() + nusynfy(), new String(\"lo\"), new String(\"ep\"), new String(\"x\"), new String(\"e\"), new String(\"vqugc\")][2]" ascii
    $s9  = "ajazc() + redivn() + bonachy() + jorve() + ydcirhu() + uclasb() + ghopa() + xofy() + orvus() + akin() + ijev() + ijuf() + urqati" ascii
    $s10 = "var itvuxumv = [new String(\"l\"), new String(\"ysw\"), new String(\"jy\"), new String(\"wi\"), new String(\"bosd\"), \"r\" + \"" ascii
    $s11 = "+ inuwzax() + banxy() + akdoxo() + wgesosl() + qluwjofy() + woke() + mgicbe() + anarzudg() + ufbukbasw() + efzoduwz() + alyqlirq" ascii
    $s12 = "var itvuxumv = [new String(\"l\"), new String(\"ysw\"), new String(\"jy\"), new String(\"wi\"), new String(\"bosd\"), \"r\" + \"" ascii
    $s13 = "ew String(\"a\"), new String(\"tacs\"), typeof XMLHttpRequest][8];" fullword ascii
    $s14 = "var saxekqozwi = [new String(\"mj\"), new String(\"e\"), new String(\"dm\"), new String(\"jtudk\"), new String(\"in\"), new Stri" ascii
    $s15 = "function zheqjytro() {" fullword ascii
    $s16 = "return [new String(\"tgy\"), new String(\"owp\"), \"r.ex\", new String(\"yjs\"), new String(\"vu\"), new String(\"i\"), new Stri" ascii
    $s17 = "return [new String(\"e\"), new String(\"i\"), \"baq=\", new String(\"u\"), new String(\"g\"), new String(\"a\"), new String(\"o" ascii
    $s18 = "function ocmylrof() {" fullword ascii
    $s19 = "w String(\"qyc\")][2];" fullword ascii
    $s20 = "w String(\"yn\"), new String(\"q\")][6];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}