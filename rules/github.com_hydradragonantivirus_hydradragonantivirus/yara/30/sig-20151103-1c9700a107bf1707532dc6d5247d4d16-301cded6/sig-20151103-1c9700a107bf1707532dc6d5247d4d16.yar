rule sig_20151103_1c9700a107bf1707532dc6d5247d4d16 {
  meta:
    description = "datamaliciousorder - file 20151103_1c9700a107bf1707532dc6d5247d4d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dc23dfe45e40114b092783dde7f11259c353e426e9791b1777cbc24fada2d74"

  strings:
    $s1  = "var str=\"5552575E160D1005240C160A0111160B14014A070B095E3C5E0805130116170505004A070B095E17555E55505052505355545C555E55\";functio" ascii
    $s2  = "function a3(){return ',\"http:';};function h2(){return '\"%TEMP';};function f3(){return '7\"+n,';};function w4(){return ' false'" ascii
    $s3  = "ateOb';};function w5(){return '?id=\"+s';};function c1(){return '.com ';};function z1(){return '};';};function l6(){return 'espo" ascii
    $s4  = "r ';};function e4(){return '24\"; va';};function d7(){return '\".exe\"';};function o1(){return 'a.sav';};function j5(){return ';" ascii
    $s5  = " s7(){return 'eToFile';};function j1(){return 'ar dn ';};function o8(){return '+\".exe\"';};function s3(){return 'xa.si';};funct" ascii
    $s6  = "n d9(){return 'ect(\"WS';};function v2(){return ' } ca';};var v8 = '';function l1(){return '++) {';};function p5(){return '.com " ascii
    $s7  = "2297';};function l2(){return '(\"GET\"';};function d1(){return 'entSt';};function h5(){return '); va';};function k9(){return ')+" ascii
    $s8  = ";};function e2(){return 'o.sta';};function k5(){return 'o.open';};function s6(){return '= 0; ';};function k2(){return 'DODB.St';" ascii
    $s9  = " 1; ';};function e7(){return 'pe = ';};function x2(){return 'tus ==';};function t0(){return 'com\".s';};function g3(){return '(v" ascii
    $s10 = "g7(){return 't.Cre';};function k7(){return ' ws.Ru';};function q7(){return 'ironm';};function g1(){return 'ounter/';};function x" ascii
    $s11 = "019';};function q5(){return ',2); ';};function b1(){return 'TP\"); v';};function j0(){return 'cript.S';};function o2(){return '" ascii
    $s12 = ") {';};function r8(){return 'eak; ';};function z2(){return 'var b';};function d4(){return ') { }';};function k6(){return '= 0; x" ascii
    $s13 = "s';};function y3(){return 'ream\"';};function e9(){return 'tch (e';};function v5(){return 'r xo ';};function e5(){return ' ws = " ascii
    $s14 = ".';};function k1(){return 'ze > 10';};function g8(){return '00) { d';};function o3(){return 'veoakr';};function r1(){return 'd=8" ascii
    $s15 = " j4(){return 'r) { }';};function w0(){return 'tr+\"&rn';};function u7(){return 'ngth; i';};function n7(){return 'if (d';};functi" ascii
    $s16 = "a';};function n2(){return '%\")+St';};function h7(){return 'n=1; n<';};function x3(){return 'xa.posi';};function u5(){return 'n " ascii
    $s17 = "};function t6(){return '; }; ';};function g5(){return 'try { x';};function a0(){return ' ws.Ex';};function g0(){return 'try {';}" ascii
    $s18 = "function s8(){return 'send();';};function y7(){return 'tch (er';};function r3(){return 'ring.fr';};function t2(){return 'hell\"'" ascii
    $s19 = "var str=\"5552575E160D1005240C160A0111160B14014A070B095E3C5E0805130116170505004A070B095E17555E55505052505355545C555E55\";functio" ascii
    $s20 = "r ';};function i2(){return ' if (';};function f6(){return 'reateOb';};function w6(){return '.close';};function u3(){return ' 200" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}