rule sig_20151013_470f57ae391aa252e90bf0d7d9005ce7 {
  meta:
    description = "datamaliciousorder - file 20151013_470f57ae391aa252e90bf0d7d9005ce7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aadad0f52e2d4a7600fdf66e872ffb8653d31936bb62a3c4f6a9d18f01f3958"

  strings:
    $s1  = "var str=\"5551575E06160D030D240C160A0111160B14014A070B095E225E101107050A0B4A070B094A06165E17011614565E55505050525C5C555C54\"; fu" ascii
    $s2  = "'); '; }; function tzg() { eec += '.exe\"'; }; function mlgt() { eec += 'ct('; }; function lufc() { eec += ' {'; }; function uyo" ascii
    $s3  = "n nhe() { eec += 'nr'; }; function cur() { eec += 'ng.f'; }; function whed() { eec += 't.Cre'; }; function kbip() { eec += 'http" ascii
    $s4  = " ' = '; }; function jkn() { eec += '.Cre'; }; function sso() { eec += 'h; '; }; function wqd() { eec += '; '; }; function drpv()" ascii
    $s5  = "+Mat'; }; function xsxh() { eec += 'a.ope'; }; function fpk() { eec += '{ ws.'; }; function dvp() { eec += 'r w'; }; function cj" ascii
    $s6  = "c += 'ol.or'; }; function oiqc() { eec += 'a.wri'; }; function uwrm() { eec += '+) { '; }; function pkzh() { eec += ' = 1'; }; f" ascii
    $s7  = " } '; }; function bbs() { eec += 'at'; }; function xrx() { eec += '4 && '; }; function uiw() { eec += ' dn '; }; function xqz() " ascii
    $s8  = "+= '+\"&r'; }; function ibra() { eec += ' fn '; }; function fijn() { eec += 'ip'; }; function tetw() { eec += ' \"d'; }; functio" ascii
    $s9  = "+\"'; }; function gfg() { eec += ');'; }; function yqhv() { eec += 'l(78'; }; function skhs() { eec += 'id'; }; function bkqm() " ascii
    $s10 = "ww() { eec += '};'; }; function esz() { eec += '.stat'; }; function vnxg() { eec += 'eBody'; }; function axkg() { eec += ');'; }" ascii
    $s11 = "+= 'n(fn'; }; function onln() { eec += 'seven'; }; function hpeh() { eec += ' dl'; }; function cwyy() { eec += 'cti'; }; functio" ascii
    $s12 = " eec += '(60'; }; function xvl() { eec += '(Math'; }; function gfyk() { eec += 'scho'; }; function fpa() { eec += '; '; }; funct" ascii
    $s13 = "ec += '=0; i'; }; function zkf() { eec += 'ch '; }; function scnb() { eec += ' 0;'; }; function rlps() { eec += 'g co'; }; funct" ascii
    $s14 = "ec += 'iado'; }; function isp() { eec += 'tio'; }; function zwq() { eec += 'Scrip'; }; function tfb() { eec += 'MLHTT'; }; funct" ascii
    $s15 = "ion tiu() { eec += '\")+St'; }; function dgl() { eec += '(xo.r'; }; function qhy() { eec += 's = W'; }; function jmy() { eec += " ascii
    $s16 = "tion yskd() { eec += '\");'; }; function yssa() { eec += 'te('; }; function vily() { eec += 'tech'; }; function xts() { eec += '" ascii
    $s17 = "n gdbm() { eec += ' (var'; }; function snlp() { eec += 'rakas'; }; function pymg() { eec += 'en'; }; function gkhw() { eec += '(" ascii
    $s18 = ") { eec += 'T\",\"'; }; function rfh() { eec += 'us'; }; var eec = ''; function bcdp() { eec += 'un'; }; function ebo() { eec +=" ascii
    $s19 = "ion zql() { eec += 'az.or'; }; function rzo() { eec += '}; dl'; }; function mhp() { eec += '.ra'; }; function dkvb() { eec += 'h" ascii
    $s20 = "var yycu = ''; function box() { eec += 'y '; }; function ndj() { eec += 'cri'; }; function fbu() { eec += ']+\"/c'; }; function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}