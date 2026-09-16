rule sig_20151011_b5ac44ce7097e95c466a41f7fa41378a {
  meta:
    description = "datamaliciousorder - file 20151011_b5ac44ce7097e95c466a41f7fa41378a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dada9b0764d7cfa486d183fdbb63a084f0a0404fa85261da3686ef9208c36121"

  strings:
    $s1  = "var str=\"5551575E080B1D0508101D240C160A0111160B14014A070B095E225E160D030317104A070B095E17011614565E55505050515C5C5C535C\"; func" ascii
    $s2  = "v() { iztg += '%TEMP'; }; function tkqv() { iztg += '\"GET\"'; }; function xba() { iztg += '();'; }; function qghu() { iztg += '" ascii
    $s3  = "; }; function zjcn() { iztg += ',\"htt'; }; function dty() { iztg += '= '; }; function dll() { iztg += 'er'; }; function hnm() {" ascii
    $s4  = "fl(); heif(); xmm(); jmtf(); efyg(); vqf(); dde(); golf(); vhj(); xpg(); dll(); mil(); vcfj(); hfms(); lfnl(); jdo(); hnm(); dpz" ascii
    $s5  = "yt() { iztg += ');'; }; function hdr() { iztg += 'Strin'; }; function yrka() { iztg += ' && x'; }; function ggs() { iztg += ' = " ascii
    $s6  = "; function rfrk() { iztg += ' xo.'; }; function iqfh() { iztg += 'rip'; }; function mxb() { iztg += 'a.sav'; }; function yobw() " ascii
    $s7  = "nction lwv() { iztg += '.pos'; }; function cmz() { iztg += '= 0;'; }; function nymp() { iztg += '; };'; }; function xwkb() { izt" ascii
    $s8  = " { iztg += ' var '; }; function hqg() { iztg += ' xa'; }; function uyl() { iztg += 'o.ope'; }; function knt() { iztg += '.writ';" ascii
    $s9  = ")'; }; function vhj() { iztg += '.org'; }; function ory() { iztg += 'ML'; }; function grr() { iztg += ' t'; }; function irf() { " ascii
    $s10 = "unction dzxe() { iztg += 'espon'; }; function ljl() { iztg += '(var '; }; function cys() { iztg += 'xo.R'; }; function xwq() { i" ascii
    $s11 = "'.spli'; }; function pmkz() { iztg += ' dl'; }; function gopk() { iztg += '); va'; }; function mds() { iztg += ' 200)'; }; funct" ascii
    $s12 = " kla() { iztg += '++) '; }; function vcfj() { iztg += 'larbo'; }; function ffq() { cmpp += 'val'; };  function jyn() { iztg += '" ascii
    $s13 = "ion vcxd() { iztg += 'us =='; }; function xmc() { iztg += 'Scri'; }; function omz() { rnt(iztg); };  function ojn() { iztg += 'u" ascii
    $s14 = "{ iztg += 'p://'; }; function ljd() { iztg += 'se'; }; function xuax() { iztg += '; '; }; function acg() { iztg += '{}; '; }; fu" ascii
    $s15 = "ction ano() { iztg += 'nd('; }; function fbom() { iztg += 'for '; }; function yyp() { iztg += 'oun'; }; function bxwv() { iztg +" ascii
    $s16 = "yst'; }; function jdo() { iztg += 'tide.'; }; function kyha() { iztg += 'LH'; };awxq(); qjne(); uxfw(); xwq(); dtue(); qghu(); p" ascii
    $s17 = "n gzv() { iztg += 'if'; }; function ust() { iztg += '(\"W'; }; function thn() { iztg += ' xa.c'; }; function tayg() { iztg += 'A" ascii
    $s18 = "n wtwi() { iztg += 'ry { '; }; function iixu() { iztg += ' var'; }; function hfms() { iztg += 'y.co'; }; function rqxf() { iztg " ascii
    $s19 = "ztg += 'l(fr)'; }; function heif() { iztg += 'vidy'; }; function rltb() { iztg += 'ty'; }; var iztg = ''; function lpgq() { iztg" ascii
    $s20 = "p'; }; function uac() { iztg += 'se'; }; function zaoc() { iztg += 'iti'; }; function axa() { iztg += ' dn '; }; function rurx()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}