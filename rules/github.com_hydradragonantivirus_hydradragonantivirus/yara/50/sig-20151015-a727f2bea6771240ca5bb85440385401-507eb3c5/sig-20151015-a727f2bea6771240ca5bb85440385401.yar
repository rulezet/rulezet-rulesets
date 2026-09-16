rule sig_20151015_a727f2bea6771240ca5bb85440385401 {
  meta:
    description = "datamaliciousorder - file 20151015_a727f2bea6771240ca5bb85440385401.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c482f20d22e730255712e4216db0630142f1b1bef9212a47ae06c50455f146d0"

  strings:
    $s1  = "var str=\"5551505E060B0300050A240C160A0111160B14014A070B095E225E0D13050A100A011317080110100116174A070B095E17011614565E555050505D" ascii
    $s2  = ") { rlnl += 'for'; }; function ddtp() { rlnl += 'Shell'; }; function nis() { rlnl += 'com'; }; function jxll() { rlnl += ' \"); " ascii
    $s3  = ") { rlnl += 'om()'; }; function zxfb() { rlnl += '.exe\"'; }; function eqn() { rlnl += 'r '; }; function jvu() { rlnl += 'tat'; " ascii
    $s4  = "ng'; }; function vlu() { rlnl += 'a.typ'; }; function mefz() { rlnl += ' { '; }; function etsw() { rlnl += 'h.ro'; }; function r" ascii
    $s5  = "n kkzr() { rlnl += ' \"al'; }; function escq() { rlnl += 'http:'; }; function tqws() { rlnl += '92)'; }; function xyi() { rlnl +" ascii
    $s6  = "qck() { rlnl += 'dn ='; }; function lqr() { rlnl += 'o.Res'; }; function khp() { rlnl += '32);'; }; function efu() { rlnl += '; " ascii
    $s7  = "= 'f ('; }; function joa() { rlnl += 'dl'; }; function cqs() { rlnl += 'Obje'; }; function wzp() { rlnl += ') {}'; }; function q" ascii
    $s8  = "{ rlnl += 't.'; }; function pzdq() { rlnl += '}; '; }; function gxfu() { rlnl += '= 4'; }; function ydfk() { rlnl += '= '; }; fu" ascii
    $s9  = "; };  function lwoz() { rlnl += 'try'; }; function rvuo() { rlnl += 'St'; }; function hye() { rlnl += 'yS'; }; function hdjw() {" ascii
    $s10 = "l += 'ec'; }; function rdw() { rlnl += 'd('; }; function mjpt() { rlnl += 'unte'; }; function eyy() { rlnl += '); i'; }; functio" ascii
    $s11 = "}; function evxa() { rlnl += 'HTT'; }; function wvur() { rlnl += '\"/co'; }; function grn() { rlnl += 'spli'; }; function ots() " ascii
    $s12 = "= '(5393'; }; function evj() { rlnl += 'rip'; }; function jss() { rlnl += '; '; }; function uifo() { rlnl += 'rand'; }; function" ascii
    $s13 = " { rlnl += '+M'; }; function kah() { rlnl += 'tion'; }; function bos() { rlnl += '\"G'; }; var rlnl = ''; function fflx() { rlnl" ascii
    $s14 = "; }; function jxl() { rlnl += 'ct'; }; function tuz() { rlnl += 'try {'; }; function usq() { rlnl += '(); x'; }; function bgeo()" ascii
    $s15 = "'; }; function lfs() { rlnl += 'f (x'; }; function uiw() { rlnl += 'dn '; }; function jdmz() { rlnl += ' ='; }; function bbj() {" ascii
    $s16 = "rlnl += 'fu'; }; function pmjp() { rlnl += 'ize'; }; function pdhq() { rlnl += 'viro'; }; function rtj() { rlnl += ') '; }; func" ascii
    $s17 = "00)'; }; function rkmi() { rlnl += 'ar'; }; function clwe() { rlnl += 'DB.'; }; function ahv() { rlnl += ' func'; }; function ls" ascii
    $s18 = "e ='; }; function mjrp() { rlnl += 'i=0'; }; function mta() { rlnl += 'onrea'; }; function oxm() { rlnl += 'ose('; }; function l" ascii
    $s19 = "ka() { rlnl += 'St'; }; function bja() { rlnl += 'a.sa'; }; function hbrr() { rlnl += 'ip'; }; function jvq() { rlnl += '*1'; };" ascii
    $s20 = "+= '200) '; }; function svbw() { rlnl += 'r '; }; function rrz() { rlnl += 'ript.'; }; function yrhm() { rlnl += 'var '; }; func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}