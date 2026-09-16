rule sig_20151001_21c9b9a42561f0daecd89ed1cf4a2a14 {
  meta:
    description = "datamaliciousorder - file 20151001_21c9b9a42561f0daecd89ed1cf4a2a14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e1267e7185514b0a7a8a5d634256e3bd21b3d020d736e8cd868016c85e62ebf"

  strings:
    $s1  = "{ pgde += '2.XML'; }; function xwxkvh() { pgde += 'fr) '; }; function gdbncvq() { pgde += '= fu'; }; function rvwxg() { pgde += " ascii
    $s2  = "'; }; function mogco() { pgde += 'EMP%'; }; function kusnns() { pgde += 'xa.w'; }; function elqrxyq() { pgde += '.fac'; }; funct" ascii
    $s3  = "yb() { pgde += '.pos'; }; function obwq() { pgde += '= 1'; }; function itcnj() { pgde += 'ta'; }; function dtxboi() { pgde += 'C" ascii
    $s4  = "uqc() { pgde += 'try '; }; function tkfazhe() { pgde += '\"%T'; }; function euap() { pgde += 'nd'; }; function yotytc() { pgde +" ascii
    $s5  = "zyjnc(); itdbepz(); vgwlim(); nchd(); crhpcvk(); imlyhpm(); lumtsb(); awcl(); iczdvj(); xext(); this[viblxe](pgde); " fullword ascii
    $s6  = "ion iytkuf() { pgde += '00)+'; }; function lvbszy() { pgde += 'typ'; }; function dgyj() { pgde += '+Str'; }; function cumthha() " ascii
    $s7  = "bsmd() { pgde += 'ew A'; }; function ehfvqp() { pgde += 'fdi'; }; function ktezpm() { pgde += 'TP\")'; }; function ixtcrho() { p" ascii
    $s8  = ".'; }; function xext() { viblxe += 'val'; };  function bykw() { pgde += '= \"c'; }; function wfods() { pgde += 'iv'; }; function" ascii
    $s9  = "ion iefrx() { pgde += 'n() '; }; function knxrzlf() { pgde += 'nct'; }; function fwxidt() { pgde += 'ent.'; }; function mfuuaz()" ascii
    $s10 = "ion'; }; function frna() { pgde += 'ph'; }; function wwfik() { pgde += 'HT'; }; function sztt() { pgde += ') '; }; function mmbs" ascii
    $s11 = "ps() { pgde += '; '; }; function hjvluui() { pgde += 'tu'; }; function ethl() { pgde += 'ady'; }; function rsjdnb() { pgde += 'c" ascii
    $s12 = "hang'; }; function ldvwfo() { pgde += '{ '; }; function uziolyj() { pgde += 'dE'; }; function oyqla() { pgde += '{ w'; }; functi" ascii
    $s13 = "ooq() { pgde += 's = '; }; function ujjlaw() { pgde += 'Obje'; }; function djvds() { pgde += '()'; }; function azqyf() { pgde +=" ascii
    $s14 = "unction rleosn() { pgde += '(e'; }; function drhqkm() { pgde += 'onse'; }; function cscwef() { pgde += 'trea'; }; function hqyuz" ascii
    $s15 = "nction kkqpmh() { pgde += 'n(f'; }; function lozm() { pgde += ' d'; }; function slil() { pgde += 'Bod'; }; function mokb() { pgd" ascii
    $s16 = "ptzns() { pgde += 'l.'; }; function sfcv() { pgde += '\"AD'; }; function hsvh() { pgde += '}; '; }; function bxnayi() { pgde += " ascii
    $s17 = "de += 'n,2)'; }; function llsse() { pgde += ' n'; }; function mipjq() { pgde += '.ro'; }; function pxnlpl() { pgde += 'ct(\"W'; " ascii
    $s18 = "ion zamundo() { pgde += 'xp'; }; function ktgfqje() { pgde += 'tch '; }; function ipykkv() { pgde += 'xa'; }; function dqbvvhn()" ascii
    $s19 = "ction ftmzucf() { pgde += ' for'; }; function osykg() { pgde += 't(\" '; }; function hbqgbrz() { pgde += ' 1; '; }; function tbi" ascii
    $s20 = "n fubko() { pgde += 'atch '; }; function timqlc() { pgde += 'ndom'; }; function dmrjvg() { pgde += 'y);'; }; function ybkdp() { " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}