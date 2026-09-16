rule sig_20151004_bebc213feb050389dfd366c6a33e5048 {
  meta:
    description = "datamaliciousorder - file 20151004_bebc213feb050389dfd366c6a33e5048.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5435a4142fb14304dbb979c97ff050562a90ba269558905320381356b3a97f09"

  strings:
    $s1  = "var str=\"5551555E060B0300050A240C160A0111160B14014A070B095E225E0F0D0A03000B090905030D0710124A070B095E17011614565E555050575D5457" ascii
    $s2  = "function xogr() { hdoo += 'en'; }; function qmf() { hdoo += ' var'; }; function hquh() { hdoo += '{ dn '; }; function owwm() { h" ascii
    $s3  = "cdz() { hdoo += 'do'; }; function kpkp() { hdoo += 'ew '; }; function yomy() { hdoo += 'GET'; }; function smuo() { hdoo += ' dn " ascii
    $s4  = "unction snot() { hdoo += '== '; }; function uytq() { hdoo += ' va'; }; function igra() { hdoo += 'Run(f'; }; function lbif() { h" ascii
    $s5  = "{ hdoo += '.clo'; }; function yzgo() { hdoo += 'Activ'; }; function ihxd() { hdoo += '713'; }; function zqi() { hdoo += '2); d';" ascii
    $s6  = "function jpfk() { hdoo += 'for '; }; function lum() { hdoo += 'b.len'; }; " fullword ascii
    $s7  = "+= 'com '; }; function vbeh() { hdoo += '= 0'; }; function dxr() { hdoo += '); x'; }; function ohx() { hdoo += '\",'; }; functio" ascii
    $s8  = "oo += 'Str'; }; function clxm() { hdoo += 'MP%\")'; }; function mfs() { hdoo += 'se);'; }; function ssa() { hdoo += 'com.b'; }; " ascii
    $s9  = "ion yrji() { hdoo += ' }'; }; function cfk() { hdoo += ':/'; }; function bpvs() { hdoo += '; dl'; }; function uzch() { hdoo += '" ascii
    $s10 = "+= 'ing.f'; }; function jlw() { hdoo += '2);'; }; function yti() { hdoo += 'ak'; }; function xtdq() { hdoo += '}; '; }; function" ascii
    $s11 = "; }; function ffim() { hdoo += ' 0'; }; function hvwc() { hdoo += 'unct'; }; function mnn() { hdoo += ' t'; }; function iqx() { " ascii
    $s12 = "() { hdoo += '\".'; }; function klc() { hdoo += 'on ='; }; function dmt() { hdoo += '}; i'; }; function pfp() { hdoo += 'a.op'; " ascii
    $s13 = "eB'; }; function iyx() { hdoo += 'ch '; }; function chrj() { hdoo += 'tr'; }; function ihqt() { hdoo += 'L2.XM'; }; function dsx" ascii
    $s14 = " += '); i'; }; function eoj() { hdoo += '; x'; }; function qrju() { hdoo += 'ings'; }; function szib() { hdoo += 'e(fn,'; }; fun" ascii
    $s15 = "function wqq() { hdoo += '\"sol'; }; function xmcn() { hdoo += 'ect('; }; function hvt() { hdoo += 'tr, f'; }; function gwy() { " ascii
    $s16 = "e'; }; function gzo() { hdoo += 'a ='; }; function xct() { hdoo += '{ var'; }; function dyx() { hdoo += 'e(xo.'; }; function byz" ascii
    $s17 = "n sagv() { hdoo += 'o '; }; function ydpj() { hdoo += 'raga'; }; function ygb() { hdoo += 'ar'; }; function dpcs() { hdoo += 'os" ascii
    $s18 = "h(); clxm(); mdb(); xrvc(); uwc(); ygb(); tpj(); tekw(); iqx(); axr(); pon(); nou(); htu(); ocgl(); acdz(); xfh(); mora(); dgxi(" ascii
    $s19 = "function wqq() { hdoo += '\"sol'; }; function xmcn() { hdoo += 'ect('; }; function hvt() { hdoo += 'tr, f'; }; function gwy() { " ascii
    $s20 = "function qfp() { ifn = this[ofbq]; };  " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}