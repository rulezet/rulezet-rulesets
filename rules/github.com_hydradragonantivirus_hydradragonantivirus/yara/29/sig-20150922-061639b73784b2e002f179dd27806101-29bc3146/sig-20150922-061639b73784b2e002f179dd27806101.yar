rule sig_20150922_061639b73784b2e002f179dd27806101 {
  meta:
    description = "datamaliciousorder - file 20150922_061639b73784b2e002f179dd27806101.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "884778b80699fd09a0833dffd861a7f794b4dd703d444dada572a218533d7488"

  strings:
    $s1  = "var str=\"5550515E0508010724011C1405101001070C4A070B09\";function ojexnmq() { ajsjn += '55'; }; function cefqnbt() { ajsjn += 't" ascii
    $s2  = "ion qmmsn() { ajsjn += 'rn'; }; function hrtmpip() { ajsjn += ' if'; }; function ofry() { ajsjn += '; '; }; function owguy() { a" ascii
    $s3  = "jsjn += '.s'; }; function wshxhr() { ajsjn += 'St'; }; function muvp() { ajsjn += 'e.net'; }; function djnq() { ajsjn += 'ocume'" ascii
    $s4  = "on ftvdu() { ajsjn += '4 && '; }; function ihks() { ajsjn += ' { '; }; function jdsanl() { ajsjn += 'ect'; }; function zkjt() { " ascii
    $s5  = "' { '; }; function xpexq() { ajsjn += 'ave'; }; function phwib() { ajsjn += '.ope'; }; function tuwtrn() { ajsjn += ' v'; }; fun" ascii
    $s6  = " 'ncti'; }; function bcsyrl() { ajsjn += ' {}; '; }; function mjmges() { ajsjn += '();'; }; function vxmcc() { ajsjn += '.clo'; " ascii
    $s7  = "jn += 'a.wri'; }; function ybmu() { ajsjn += 'XObj'; }; function bmdph() { ajsjn += 'l(234'; }; function tmxxwr() { ajsjn += 'om" ascii
    $s8  = "function qoakjfb() { ajsjn += '.read'; }; function vqow() { ajsjn += '\")+S'; }; function sjwol() { ajsjn += 'und'; }; function " ascii
    $s9  = "ction fujxk() { ajsjn += 'a.pos'; }; function eqli() { ajsjn += ' \"ch'; }; function ozqrdo() { ajsjn += ' } c'; }; function gcn" ascii
    $s10 = ") { ajsjn += 'ition'; }; function potzcfn() { ajsjn += 'n('; }; function zbkeska() { ajsjn += 'B.Str'; }; function hbegknb() { a" ascii
    $s11 = "function lutbpz() { ajsjn += ' > 5'; }; function jxjuqan() { ajsjn += 'al'; }; function vezdnk() { ajsjn += '(\"MSX'; }; functio" ascii
    $s12 = "}; function subtdfw() { ajsjn += 'ode(9'; };gmygt(); aftowe(); yxta(); sipmmg(); xishov(); pxtjti(); eiqrcn(); eqli(); xcnpxvn()" ascii
    $s13 = "lt() { ajsjn += ' i'; }; function mzmm() { ajsjn += ' = 0;'; }; function anng() { ajsjn += 'reak'; }; function doalp() { ajsjn +" ascii
    $s14 = "\".'; }; function buvc() { ajsjn += ' x'; }; function tnxmxo() { ajsjn += 'xo.'; }; function homijrs() { ajsjn += 'spon'; }; fun" ascii
    $s15 = "gi() { ajsjn += 'eady'; }; function titl() { ajsjn += 'ize'; }; function zdsr() { ajsjn += 'le('; }; function qvth() { ajsjn += " ascii
    $s16 = "jsjn += '(er) '; }; function zics() { ajsjn += 'pi'; }; function ngsbyb() { ajsjn += 'dl(5'; }; function bnmgwo() { ajsjn += ' x" ascii
    $s17 = "() { ajsjn += 'Expa'; }; function tqmxx() { ajsjn += 'ar i'; }; function fzdi() { ajsjn += 'rC'; }; function nfiag() { ajsjn += " ascii
    $s18 = "fjm() { ajsjn += '8342)'; }; function sipmmg() { ajsjn += ' dl('; }; function yrkwwh() { ajsjn += 'atc'; }; function ydtckr() { " ascii
    $s19 = "}; function ptuq() { ajsjn += '2)'; }; function adymnt() { ajsjn += 'un(fn'; }; function nlmzr() { ajsjn += ' = fu'; }; function" ascii
    $s20 = " }; function bjxc() { ajsjn += 'dl('; }; function vbwchd() { ajsjn += 'ring'; }; function coasxsk() { ajsjn += 'nvir'; }; functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}