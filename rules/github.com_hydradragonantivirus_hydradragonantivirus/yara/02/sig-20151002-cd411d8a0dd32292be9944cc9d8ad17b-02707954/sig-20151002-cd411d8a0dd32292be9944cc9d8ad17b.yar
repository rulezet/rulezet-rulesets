rule sig_20151002_cd411d8a0dd32292be9944cc9d8ad17b {
  meta:
    description = "datamaliciousorder - file 20151002_cd411d8a0dd32292be9944cc9d8ad17b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ca9867826861e2cfd1b29628adfccf72ee59a5478e5c6662ef304863cf63c00"

  strings:
    $s1  = "var str=\"55505D5E0508010724011C1405101001070C4A070B095E225E101107050A050855544A070B095E17011614565E555050575C545650525C\";funct" ascii
    $s2  = "nction mzgs() { vinv += '\"GET'; }; function xkmx() { vinv += 'fun'; }; function dwib() { vinv += '822);'; }; function lfawg() {" ascii
    $s3  = "zsz() { vinv += 'eak'; }; function fomous() { vinv += 'Objec'; }; function ureadm() { vinv += 'tre'; }; function teprd() { vinv " ascii
    $s4  = " function grjploq() { vinv += ' x'; }; function vmhqf() { vinv += 'ar f'; }; function jzmxx() { vinv += '.She'; }; function vofx" ascii
    $s5  = "{ vinv += 'a.wri'; }; function meuanxe() { vinv += 'd(M'; }; function xofk() { vinv += ' i<b.'; }; function dwvw() { vinv += 'd(" ascii
    $s6  = "nv += 'an'; }; function aoyvy() { vinv += 'ry'; }; function wikho() { vinv += 'am\")'; }; function hnxtwpt() { vinv += '4 && '; " ascii
    $s7  = "n dlcgqg() { vinv += 'elm'; }; function kxhurk() { vinv += 'ctiv'; }; function eustoxo() { vinv += ' (xo'; }; function oxov() { " ascii
    $s8  = " }; function ynlpbmd() { vinv += 'dymob'; }; function fvrs() { vinv += 'ile.c'; }; function jecubj() { vinv += 'n = 1'; }; funct" ascii
    $s9  = "tion xmjyzj() { vinv += 'ion'; }; var vinv = ''; function bqwznr() { vinv += '() '; }; function ublqa() { vinv += 'o.'; }; funct" ascii
    $s10 = "; }; function hbkm() { vinv += '0)+'; }; function rbgeosi() { vinv += 'tStr'; }; function rfcuox() { vinv += ' d'; }; function l" ascii
    $s11 = "{ vinv += '.r'; }; function tasy() { vinv += 'ad'; }; function piapq() { vinv += '.s'; }; function rerm() { vinv += 'ing'; }; fu" ascii
    $s12 = "== '; }; function myauzz() { vinv += 'if '; }; function wecv() { vinv += 'rke'; }; function teacnt() { vinv += 'ak.c'; }; functi" ascii
    $s13 = "nh() { vinv += '=0;'; }; function fkttl() { vinv += 'le'; }; function uwrc() { nxyjb += 'e'; };  function mzrqo() { vinv += 'ToF" ascii
    $s14 = "; }; function hhbxu() { vinv += 'nvi'; }; function eupwq() { vinv += ')+M'; }; function wxif() { vinv += 'ew A'; }; function bak" ascii
    $s15 = "); cgnjsr(); dwib(); rfcuox(); tanaorz(); giwomto(); xqwnbo(); uwrc(); sgmiw(); this[nxyjb](vinv); " fullword ascii
    $s16 = "v += 'n '; }; function zdlry() { vinv += '?rnd'; }; function cgnjsr() { vinv += '(6'; }; function dfubem() { vinv += ' > 5'; }; " ascii
    $s17 = " 'ct'; }; function umvrnf() { vinv += 't(\"'; }; function qarndzw() { vinv += 'php'; }; function xbouqkp() { vinv += 'yst'; }; f" ascii
    $s18 = "'=\"+fr'; }; function wzocd() { vinv += 'P\");'; }; function hrdloy() { vinv += 'an'; }; function sbdv() { vinv += 'i++) '; }; f" ascii
    $s19 = "nv += 'Resp'; }; function xtpnvmr() { vinv += '1)'; }; function slxliwz() { vinv += 'ew '; }; function hpues() { vinv += 'los'; " ascii
    $s20 = "nv += '); '; }; function qmdh() { vinv += '};'; }; function xdhjia() { vinv += 'h ('; }; function zqrvlu() { vinv += '== 1)'; };" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}