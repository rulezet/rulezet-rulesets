rule sig_20151027_af35d08628727df846d5db186ef2c079 {
  meta:
    description = "datamaliciousorder - file 20151027_af35d08628727df846d5db186ef2c079.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bef7c277ac1fd8c046193d7c1ce6720afce09deb0d0c5248f394be5a572ac193"

  strings:
    $s1  = "var str=\"55515D5E17050D0005240C160A0111160B14014A070B095E305E050810051005131305164A070B095E17555E555050515D5452545C545E55\"; fu" ascii
    $s2  = "yat() { lfad += '896'; }; function eee() { lfad += 'abama'; }; function uhd() { lfad += 'com\".'; }; function ermw() { lfad += '" ascii
    $s3  = "mn() { lfad += 'Stri'; }; function ilrq() { lfad += 'Run'; }; function yfup() { lfad += '= ws'; }; function cqqh() { lfad += 'ci" ascii
    $s4  = "; function fkck() { lfad += '.org '; }; function cip() { lfad += '<b.l'; }; function okjo() { lfad += '1; n'; }; function lhni()" ascii
    $s5  = " += 're'; }; function dchd() { lfad += 'eateO'; }; function wewy() { lfad += 'osit'; }; function ris() { lfad += ' 0;'; }; funct" ascii
    $s6  = " oxbk() { lfad += 'r xa '; }; function gvt() { lfad += '; '; }; function dvd() { lfad += 'li'; }; function pkj() { lfad += 'WScr" ascii
    $s7  = " function kir() { lfad += '24\"'; }; function ytw() { lfad += '.E'; }; function xuwg() { lfad += ' ='; }; function wuv() { lfad " ascii
    $s8  = "}; function isul() { lfad += 'snero'; }; function cymj() { lfad += 'bje'; }; function gjr() { svq = this; };  function bxli() { " ascii
    $s9  = "; function coa() { lfad += 'eng'; }; function mfmp() { lfad += 'Shel'; }; function xbeh() { lfad += 'm '; }; function zsli() { l" ascii
    $s10 = " += 'oFi'; }; function pcsy() { lfad += ' n++)'; }; var ljam = ''; function eon() { lfad += '); xa'; }; function tkt() { lfad +=" ascii
    $s11 = "() { lfad += 'pt.'; }; function rkoe() { lfad += '\")'; }; function ges() { lfad += '119\"'; }; function aeut() { lfad += 'ri'; " ascii
    $s12 = " jqg() { lfad += ' };'; }; function ffqw() { lfad += '.sa'; }; function gwvr() { lfad += '(xo'; }; function ypwh() { lfad += 'ex" ascii
    $s13 = "}; function alk() { lfad += 'ar i'; }; function sbi() { lfad += '.r'; }; function sdk() { lfad += '(e'; };mogy(); ogee(); eee();" ascii
    $s14 = " jyx() { lfad += 'th'; }; function qgon() { ljam += 'ev'; };  function xue() { fzx(lfad); };  function pswj() { lfad += 'pe '; }" ascii
    $s15 = "= 'r) {'; }; function zug() { lfad += 'xp'; }; function fsuv() { lfad += ' var '; }; function cgy() { lfad += 'sof'; }; function" ascii
    $s16 = "tion ihn() { lfad += ' va'; }; function rhq() { lfad += 'xa.'; }; function iyap() { lfad += 'teO'; }; function jyrg() { lfad += " ascii
    $s17 = "on noyp() { lfad += ' };'; }; function pmb() { lfad += 'xo.o'; }; function cbf() { lfad += ' { ld'; }; function ynpb() { lfad +=" ascii
    $s18 = "'/co'; }; function udi() { lfad += '1; xa'; }; function pitu() { lfad += ' }; i'; }; function ywrs() { lfad += '{ '; }; function" ascii
    $s19 = " { lfad += '2)+'; }; function fbkn() { lfad += '(\"ADO'; }; function qfbm() { ljam += 'al'; };  function njqh() { lfad += 'nt'; " ascii
    $s20 = "() { lfad += 'size '; }; var lfad = ''; var svq = ''; function dho() { lfad += ' xa'; }; function fpa() { lfad += 't.Cr'; }; fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}