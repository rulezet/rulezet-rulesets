rule sig_20151103_a57a09bd7eb110b3a32889f3cfa950ab {
  meta:
    description = "datamaliciousorder - file 20151103_a57a09bd7eb110b3a32889f3cfa950ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3c84e113006f8c1b215f8c966fa2974e50afde3821a2372a546f4e1348a14ba"

  strings:
    $s1  = "var str=\"5552575E0D0A020B24060108130B0B000A1D4A070B095E3C5E070B0A170B161E0D0B110A0D120116170D1005160D0B0516070C0D090100014A0D10" ascii
    $s2  = "n 'y { xo';};function k4(){return 'n++) { ';};function w2(){return 'tus ==';};function u2(){return 'r.com';};function k9(){retur" ascii
    $s3  = ";};function u1(){return '.exe\"';};function u6(){return '}; xa.';};function n0(){return 'Object(';};var m2 = '';function x0(){re" ascii
    $s4  = "5(){return 'Create';};function r4(){return ' ws.Run';};function b4(){return 'if (dn';};function q9(){return '92)+\"9';};function" ascii
    $s5  = "rn ' = WS';};function z4(){return 'Script.';};function a2(){return 't(\"ADO';};function a0(){return 'File(fn';};function p4(){re" ascii
    $s6  = "{return '; bre';};function i9(){return eval;};function d8(){return '\"GET\"';};function m1(){return 'dy); ';};function j8(){retu" ascii
    $s7  = "(){return 'om kenn';};function c2(){return ') { l';};function k3(){return 'o.sta';};function z2(){return 'for (';};function g9()" ascii
    $s8  = "return 'h (er) ';};function n5(){return '\".split';};function j3(){return 'Object(';};function u4(){return 'i<b.len';};function " ascii
    $s9  = "urn 'DB.Str';};function i5(){return 'String';};function o2(){return 'nseBo';};function y6(){return ' == 1';};function t4(){retur" ascii
    $s10 = " '=\"+str+';};function a8(){return '; var ';};function h9(){return '/count';};function j7(){return '{ }; ';};m2+=j5();m2+=h2();m" ascii
    $s11 = "x8(){return 'teObjec';};function h7(){return 'ar dn =';};function q2(){return '36026';};function p5(){return 'd = 0';};function " ascii
    $s12 = ";};function f2(){return 'var x';};function k8(){return 'ncent.c';};function q8(){return 'P%\")+St';};function s6(){return ' { xa" ascii
    $s13 = "7(){return ' 0; tr';};function v5(){return '; for';};function o6(){return 'a = W';};function d6(){return 'ak; }; ';};function o5" ascii
    $s14 = "){return '=ld; ';};function u3(){return '+n+\".ex';};function b0(){return ' (var';};function i4(){return '; try {';};function z3" ascii
    $s15 = ";function l9(){return 'rite(xo';};function l0(){return 'l\"); ';};function a9(){return '.saveTo';};function o1(){return 'nd();';" ascii
    $s16 = "return 'er/?id';};function i7(){return '; xo.se';};function n3(){return '0; xa';};function j2(){return '{ dn = ';};function v0()" ascii
    $s17 = "){return 'edy.si';};function t6(){return 'd = i';};function l5(){return 'TTP\"); ';};function x7(){return '); xa.t';};function g" ascii
    $s18 = "6(){return '\"&rnd=';};function r0(){return '.posit';};function g0(){return 's.Expa';};function e0(){return '04690\"';};function" ascii
    $s19 = "){return 'var f';};function t9(){return '.respo';};function c1(){return '.open(';};function w7(){return 'Scrip';};function u0(){" ascii
    $s20 = ";function r1(){return 'ype = ';};function k5(){return '\"WScri';};function s2(){return 'pt.Shel';};function r2(){return ' if (x'" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}