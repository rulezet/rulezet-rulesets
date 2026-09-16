rule sig_20151007_41b2a305871df68fc8eee44175ff4cfd {
  meta:
    description = "datamaliciousorder - file 20151007_41b2a305871df68fc8eee44175ff4cfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76b578392146c06f78f00ff3408f7fcd6d7b27dbb3a18ef675ad991181348e81"

  strings:
    $s1  = "var str=\"5551575E060B0300050A240C160A0111160B14014A070B095E225E0805130116170505004A070B095E17011614565E55505050565157505153\"; " ascii
    $s2  = "'; }; function rshm() { kuar += '\"reye'; }; function kyo() { kuar += 'var '; }; function nyjl() { kuar += '{}'; }; function xvc" ascii
    $s3  = "al() { kuar += 'sp'; }; function pagj() { kuar += '\"GET\"'; }; function pqi() { kuar += ' == '; }; function eswu() { kuar += '/" ascii
    $s4  = " cjz() { kuar += 'nd('; }; function vouf() { kuar += ' && '; }; function rqjg() { kuar += 'r ws '; }; function fvju() { kuar += " ascii
    $s5  = "wa() { kuar += ' if ('; }; function ocj() { kuar += '.Str'; }; function mzlh() { kuar += 'xa.'; }; function varc() { kuar += 'ct" ascii
    $s6  = "on tjr() { kuar += 'Run'; }; function hohh() { kuar += 'an'; }; function dzbr() { kuar += 'ody);'; }; function ykhb() { kuar += " ascii
    $s7  = "+= '00'; }; function sgz() { kuar += 'f (dn'; }; function yml() { kuar += 'th'; }; function yqpp() { kuar += '.rou'; }; function" ascii
    $s8  = "nction cera() { kuar += 'xo.R'; }; var kuar = ''; function xtq() { kuar += 'nread'; }; function ect() { kuar += ') { v'; }; func" ascii
    $s9  = "}; function kfnt() { kuar += 'fis'; }; function tikd() { kuar += 'nmen'; }; function zygx() { kuar += '(xo'; }; function scyv() " ascii
    $s10 = "ion cba() { kuar += 's ='; }; function lgp() { kuar += '}; };'; }; function msx() { kuar += '= WS'; }; function yrh() { kuar += " ascii
    $s11 = "P%'; }; function fqso() { slxm(kuar); };  function egvk() { kuar += 'DB'; }; function vrns() { kuar += 'nviro'; }; function mxma" ascii
    $s12 = "{ kuar += 'ri'; }; function thow() { kuar += '; xa'; }; function vurl() { kuar += ' for'; }; function ggb() { kuar += 'fa'; }; f" ascii
    $s13 = "() { kuar += 'je'; }; function nzpm() { kuar += '= 1'; }; function blqy() { kuar += 'tr+\"'; }; function nzi() { kuar += 'MSXM';" ascii
    $s14 = " }; function ckk() { kuar += 'dn ='; }; function hwr() { kuar += 'tu'; }; function uxe() { kuar += '1,0)'; }; function qhq() { k" ascii
    $s15 = "{ kuar += ' i<b'; }; function uhd() { kuar += ' xo '; }; function amiq() { kuar += 'Cr'; }; function mmbj() { kuar += '\");'; };" ascii
    $s16 = " sxyd() { kuar += '); '; }; function sit() { kuar += ' t'; }; function yrb() { kuar += 'eObje'; }; function cfuv() { kuar += '; " ascii
    $s17 = "dg() { kuar += ' xo.s'; }; function irsk() { kuar += 'n()'; }; function tqxg() { kuar += 'xo.s'; }; function dpv() { kuar += 'ta" ascii
    $s18 = "'; }; function bzlo() { kuar += '; i++'; }; function xti() { kuar += ',\"'; }; function nzp() { kuar += '.XMLH'; }; function kol" ascii
    $s19 = "lxm = this[ihhp]; };  function due() { kuar += 'dn '; }; function asmq() { kuar += ' xo.o'; }; function bal() { kuar += '2)+M'; " ascii
    $s20 = "'io'; }; function pklq() { kuar += 't i'; }; function dbda() { kuar += ' { '; }; function mxhs() { kuar += 'ript.'; }; function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}