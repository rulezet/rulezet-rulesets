rule sig_20151027_151492e1d0e858f906f48859e724db3b {
  meta:
    description = "datamaliciousorder - file 20151027_151492e1d0e858f906f48859e724db3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2c887eaad2c06f5ba33f1486a61a4cc2e0bc303a43a535654de0e95bf8489c4"

  strings:
    $s1  = "var str=\"55515D5E0A0D0108174A0E0501070F0108240901100508090D0A00174A070B095E305E0E0E4917010B4A070A5E17555E555050515D5050565D515E" ascii
    $s2  = "rite'; }; function qoc() { djel += '\".exe'; }; function oil() { djel += 'anam'; }; function vup() { djel += 'rip'; }; function " ascii
    $s3  = "ction cgni() { djel += 's.Run'; }; function plnk() { djel += 'b[i]+'; }; function tti() { djel += 'osit'; }; function frp() { dj" ascii
    $s4  = "lbsb() { djel += 'e = '; }; function mvgd() { djel += ' if '; }; function iqm() { djel += 'WS'; }; function jtv() { djel += 'GET" ascii
    $s5  = " { djel += 'eToF'; }; function akg() { djel += 'ream\"'; }; function atu() { djel += '.fro'; }; function hbvs() { djel += 'ipt.'" ascii
    $s6  = "'; }; function thw() { djel += '\"/cou'; }; function ifjg() { djel += 'cia'; }; function run() { djel += 'St'; }; function fvir(" ascii
    $s7  = "tion vos() { djel += '};'; }; function mda() { djel += 'tr+'; }; function ize() { djel += 'a.ope'; }; function nme() { djel += '" ascii
    $s8  = "function qnj() { djel += ' = 0;'; };xdyn(); pdi(); zau(); astn(); drm(); eum(); dfxy(); uwf(); dfwz(); zbnp(); pgp(); oil(); iiy" ascii
    $s9  = "Sc'; }; function gfg() { djel += 'ect('; }; function rseu() { djel += 's = '; }; function hncx() { djel += 'ar xa'; }; function " ascii
    $s10 = " { djel += 'n, '; }; function cht() { djel += 'n+n+'; }; function lhsb() { djel += '\",1'; }; function hoe() { djel += '; '; }; " ascii
    $s11 = "'; }; function hclw() { djel += '60\"; '; }; function bmek() { djel += '};'; }; function huil() { djel += '<=3; '; }; function t" ascii
    $s12 = "lvgk() { djel += 'Sh'; }; function yqel() { djel += '; '; }; function cjc() { djel += 'ile('; }; function ssd() { djel += 'ion';" ascii
    $s13 = " }; function cfa() { djel += ' xa.s'; }; function srbd() { djel += ' 0'; }; function sehm() { djel += 'xa.cl'; }; function xul()" ascii
    $s14 = "'; }; function uwp() { djel += 'ell\")'; }; function cjp() { djel += 'de(9'; }; function kjo() { djel += 'rip'; }; function kvb(" ascii
    $s15 = ") { djel += '(\"ADO'; }; function xmqm() { djel += '{ '; }; function qfl() { djel += ' fn '; }; function avf() { djel += 'if '; " ascii
    $s16 = "ng'; }; function aay() { djel += 'ngs'; }; function yds() { djel += 'Expa'; }; var ogtq = ''; function uwl() { djel += '?i'; }; " ascii
    $s17 = "; }; function pvm() { djel += '.co'; }; function ofwa() { djel += 'at'; }; function lsr() { djel += 'ti'; }; function fcw() { dj" ascii
    $s18 = "mcy() { djel += '(dn'; }; function lcp() { djel += 'Body'; }; function wns() { djel += ' xo '; }; function hnti() { djel += 'xa." ascii
    $s19 = "5\"; function dooj() { djel += 'oisr'; }; function cjt() { djel += '; for'; }; function bzr() { djel += 'fn+n'; }; function bkx(" ascii
    $s20 = "'; }; function gqu() { djel += 'h (er'; }; function yhl() { djel += '); va'; }; function irsg() { djel += '> 10'; }; function ax" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}