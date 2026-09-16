rule sig_20151106_207328cb65f2fbfad16ff4b69d44d7f0 {
  meta:
    description = "datamaliciousorder - file 20151106_207328cb65f2fbfad16ff4b69d44d7f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d07d4789070c1e0d9965f42ca70d6f6aaa17fd2e59b555c9e3ab5e709a9f983e"

  strings:
    $s1  = "var str=\"5552505E050A001D240C05120108050A004A070B095E3C5E020510100B160D05060116100507070D0A0D4A0D105E17555E55505052535C5254525C" ascii
    $s2  = "';};function v9(){return '.length';};function d7(){return '.com\".';};function q8(){return 'ar i=ld';};function h4(){return ' xo" ascii
    $s3  = ":';};function i0(){return 'ell\");';};function h0(){return '.exe\",';};function o2(){return 'r n=1; ';};function c5(){return 'de" ascii
    $s4  = ";function k3(){return 'veToF';};function b4(){return '+\".exe';};function a4(){return '9\"+n, ';};function a8(){return 'DODB.';}" ascii
    $s5  = "};function f7(){return ' = \"li';};function j9(){return 'n(\"GET\"';};function c8(){return 'nmentS';};function d8(){return ') { " ascii
    $s6  = " ';};function x6(){return 'r (va';};function x2(){return '//\"+b[i';};function g6(){return 'ws.Ru';};function m2(){return ',\"ht" ascii
    $s7  = " ';};function s8(){return '.close';};function r6(){return 'ma.org';};function x8(){return 'ype = ';};function l2(){return 'eak; " ascii
    $s8  = "a.pos';};function o5(){return '= 0; ';};function h3(){return 'Enviro';};function i9(){return ' xo.se';};function r1(){return 'g." ascii
    $s9  = " (v';};function x3(){return ' = ws.E';};function s3(){return 'eBody);';};function y1(){return 'com aba';};function d4(){return '" ascii
    $s10 = "'(\"WScr';};function y0(){return ']+\"/c';};function b5(){return 'n<=3; n';};function h1(){return 'try {';};function l1(){return" ascii
    $s11 = "fromC';};function m4(){return '.size >';};function y8(){return 'split';};function k1(){return 'ipt.Sh';};function y5(){return 't" ascii
    $s12 = "s(\"%TE';};function y6(){return '(\" \");';};function a9(){return 'nd(); i';};function r4(){return ' == 200';};function u2(){ret" ascii
    $s13 = "ar x';};function r0(){return 'ition ';};function b6(){return '2); t';};function n9(){return 'ject(\"A';};function j4(){return ' " ascii
    $s14 = ";};function v4(){return 'teObjec';};function p9(){return 'MP%\")+';};function p2(){return 'status';};function z6(){return 'n = 0" ascii
    $s15 = ";function d2(){return '= 0; fo';};function u5(){return 'eateOb';};function l7(){return '); xa.t';};function f5(){return '=\"+str" ascii
    $s16 = " };';};function t1(){return '+\"&rn';};function c6(){return eval;};function h8(){return 'var b';};function j3(){return 'ile(f';}" ascii
    $s17 = "2';};function o9(){return 'spons';};function e8(){return 'ar xa ';};function g1(){return 'r/?id';};function u1(){return 'f (xo.'" ascii
    $s18 = "n ' var w';};function q5(){return 'ipt.Cr';};function p5(){return 'reate';};function v6(){return ') { d';};function w2(){return " ascii
    $s19 = "Strin';};function c1(){return '(); };';};function t4(){return 'xo.re';};function v0(){return 'tring';};function x7(){return 'n(f" ascii
    $s20 = "ope';};function h9(){return 'tch (er';};function k6(){return 'ar ld ';};function r5(){return 'ript.C';};function j2(){return '};" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}