rule sig_20151116_c1882b085e9b7d7d39e19dd66bdce5f7 {
  meta:
    description = "datamaliciousorder - file 20151116_c1882b085e9b7d7d39e19dd66bdce5f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7454f8a88d7a194df9882ba893c63455f5678b02a5d5fbcbcdf74d23bc509c24"

  strings:
    $s1  = "var str=\"5552525E0D0A020B24060108130B0B000A1D4A070B095E3C5E1C0A49495C54050201540508004A1C0A49491455050D5E17555E5550505352525251" ascii
    $s2  = "\".exe';};function u4(){return 'try {';};function s4(){return 'TEMP%\")';};function a7(){return ' { dn';};function c8(){return '" ascii
    $s3  = "= 1;';};function f2(){return 'er/?i';};function q7(){return 'ADODB.S';};function y8(){return '.com.br';};function g7(){return 'p" ascii
    $s4  = "nction m0(){return 't.Shell';};function c0(){return 'harCod';};function l4(){return 'dy); i';};function x5(){return ' == 20';};f" ascii
    $s5  = "n 'tr+\"&rn';};function j2(){return 'a.typ';};function f4(){return 'nvironm';};function o8(){return 'tp://';};function z8(){retu" ascii
    $s6  = "function q8(){return 'tatus';};function s7(){return '+\"480';};function x1(){return '\".spl';};function r4(){return 'r xa =';};f" ascii
    $s7  = "n 'Scrip';};function l9(){return '.send';};function n2(){return 't.Cre';};function y7(){return 'd=96210';};function f3(){return " ascii
    $s8  = "n '> 1000)';};function s9(){return ' 1) { ';};function i3(){return 'xa.clo';};function r7(){return '; if ';};function h1(){retur" ascii
    $s9  = "rn 'e\",2); ';};function w1(){return ' ws.R';};function j6(){return 'pt.Cre';};function w3(){return '3; n+';};function u9(){retu" ascii
    $s10 = "n 'XMLHTTP';};function r3(){return 'n+\".ex';};function y5(){return 'ET\",\"ht';};function v4(){return '; var w';};function d1()" ascii
    $s11 = "ript.Cr';};function b9(){return 'ery.c';};function n1(){return '1; n<=';};function p2(){return 'ch (er)';};function g0(){return " ascii
    $s12 = "'ject(\"';};function d8(){return 'er) { }';};function b7(){return 'ort.co';};function w7(){return 'eateOb';};function o4(){retur" ascii
    $s13 = "s(\"%';};function c1(){return '\"); v';};function a3(){return ') { var';};function q2(){return ' WScri';};function d5(){return '" ascii
    $s14 = "};function h4(){return ' { };';};function t3(){return '); xo';};function m7(){return '+) { fo';};function z6(){return 'ld = ';};" ascii
    $s15 = "(xa';};function a6(){return 'tream\"';};function o9(){return 'ar fn';};function k9(){return '8\"+n,';};function p8(){return '0) " ascii
    $s16 = "unction e5(){return '984\"; ';};function d6(){return '\",1,0);';};function b1(){return 'r (va';};h5=u1();u3+=h5;h5=b0();u3+=h5;h" ascii
    $s17 = "turn z7;};function o0(){return 'ect(\"';};function d4(){return '0; try ';};function c6(){return 'Scrip';};function h2(){return '" ascii
    $s18 = " = 1';};function x6(){return '\"+b[i]+';};function y3(){return 'ite(xo.';};function g4(){return 'e(92)';};function f5(){return '" ascii
    $s19 = "x';};function w9(){return '.size ';};function w0(){return 'respo';};function m2(){return '\"); va';};function r5(){return ' fals" ascii
    $s20 = " = WSc';};function q5(){return 'nseBo';};function l0(){return 'length';};function o2(){return 'g.fromC';};function n6(){return '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}