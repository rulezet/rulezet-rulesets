rule sig_20151010_4f27b7f2e157fef5288a449ed491e38a {
  meta:
    description = "datamaliciousorder - file 20151010_4f27b7f2e157fef5288a449ed491e38a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87db8eb344d1519e1ad6627a36b1cc05924c9e44bce3ddb0812a56046a22078c"

  strings:
    $s1  = "unction ygxl() { ocj += '\"); '; }; function lhx() { ocj += '(dn'; }; function irkc() { ocj += 'g.fro'; }; function uvf() { ocj " ascii
    $s2  = " { ocj += '; xa'; }; function tgvw() { ocj += '.sen'; }; function tfm() { ocj += 'ipt.'; }; function bhej() { ocj += ' xo'; }; f" ascii
    $s3  = " }; function brlp() { ocj += 'nd=\"'; }; function ovx() { ocj += ' { '; }; function ytc() { ocj += '.len'; }; function pvtw() { " ascii
    $s4  = "= '); '; }; function fshf() { ocj += 'blics'; }; function ndi() { ocj += 'tp:'; }; function zupw() { ocj += 'a.siz'; }; function" ascii
    $s5  = "cj += 'ipt.'; }; function pfj() { ocj += '1)'; }; function yzdj() { ocj += 'LHTTP'; }; function kofu() { ocj += '/?id='; }; func" ascii
    $s6  = "var str=\"5551575E0D0A020B24011C1405101001070C4A070B095E225E130D0A011705030B030B4A070B094A05115E17011614565E555050505053565D5554" ascii
    $s7  = "on() { ocj += 'pli'; }; function sxdn() { ocj += 'm '; }; function nvpl() { vyt(ocj); };  function piz() { ocj += 'ws.E'; }; fun" ascii
    $s8  = "jhg() { ocj += 'st'; }; function ncyy() { ocj += '; dl('; }; function lgue() { ocj += 'onrea'; }; function gco() { ocj += 'ewt';" ascii
    $s9  = " zvn() { ocj += 'Creat'; }; function olxo() { ocj += 'andEn'; }; function foyi() { ocj += ' ('; }; function nzn() { ocj += 'ect'" ascii
    $s10 = ") { ocj += 'MSX'; }; function btom() { ocj += ' }; }'; }; function dgr() { ocj += '.posi'; }; function tjq() { ocj += 'dn'; }; f" ascii
    $s11 = "nction tjyu() { ocj += 'dy'; }; function hkr() { ocj += 'or '; }; function giq() { ocj += 'ion'; }; function vmd() { ocj += 'rea" ascii
    $s12 = "+= 'abama'; }; function nif() { ocj += '(\"WS'; }; function udt() { ocj += '.ty'; }; function zkl() { ocj += 'xo.re'; }; functio" ascii
    $s13 = ")'; }; function ydlw() { ngyf += 'e'; };  function vsbt() { ocj += 'Mat'; }; function jcj() { ocj += 'e(x'; }; function xhcp() {" ascii
    $s14 = "unction ttj() { ocj += ' xa '; }; function efo() { ocj += 'pe '; }; function nezu() { ocj += '.clos'; }; function aan() { ocj +=" ascii
    $s15 = "ction wjx() { ocj += ' = '; }; function cyjp() { ocj += ' \"vi'; }; function mexp() { ocj += 'Creat'; }; function nxzb() { ocj +" ascii
    $s16 = "function yhf() { ocj += 'roun'; }; function wpl() { ocj += 'exe'; }; function ybnd() { ocj += 'ces.'; }; function bdua() { ocj +" ascii
    $s17 = " += 'ript'; }; function fjou() { ocj += 'hang'; }; function plq() { ocj += '= WSc'; }; function aon() { ocj += ' = '; }; functio" ascii
    $s18 = " ocj += 'ML'; }; function pfvq() { ocj += 'cho'; }; var ngyf = ''; function qvl() { ocj += 'h.'; }; function kxxg() { ocj += '; " ascii
    $s19 = " spel() { ocj += '; dl'; }; function ssy() { ocj += '\")+St'; }; function gen() { ocj += 'at'; }; function pxvy() { ocj += ' 2';" ascii
    $s20 = "tion rkvr() { ocj += 'ide.'; }; function sszr() { ocj += 'e = '; }; function cbyn() { ocj += 'e > 1'; }; function dlhn() { ocj +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}