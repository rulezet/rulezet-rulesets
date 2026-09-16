rule sig_20160812_782b3001810e0b8d3e43b4114eb2ee49 {
  meta:
    description = "datamaliciousorder - file 20160812_782b3001810e0b8d3e43b4114eb2ee49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "848379228a7c5829d946e01bd6de2dbdd9a2858f8210b03bd7356aa2cca04302"

  strings:
    $x1  = "var f18 = new Array(); function w97(w87) { return w87; }; function m74(b69,l73) { f18[l73] = b69; }; m74(w97('\"    '),644); fun" ascii
    $s2  = ",773); function j73(b69,l73) { f18[l73] = b69; }; j73(w97('u ex'),616); function z83(b69,l73) { f18[l73] = b69; }; z83(w97('.exe" ascii
    $s3  = "}; w80(w97('en'),708); function k15(b69,l73) { f18[l73] = b69; }; k15(w97(' /c c'),800); function u72(b69,l73) { f18[l73] = b69;" ascii
    $s4  = " }; h78(w97('P%'),92); function w73(b69,l73) { f18[l73] = b69; }; w73(w97(' /c RE'),689); function p41(b69,l73) { f18[l73] = b69" ascii
    $s5  = "}; g11(w97('+\"'),834); function g63(b69,l73) { f18[l73] = b69; }; g63(w97('  - Yo'),645); function m24(b69,l73) { f18[l73] = b6" ascii
    $s6  = "unction a30(b69,l73) { f18[l73] = b69; }; a30(w97(' /t '),721); function z20(b69,l73) { f18[l73] = b69; }; z20(w97('arCode'),19)" ascii
    $s7  = ",112); function m99(b69,l73) { f18[l73] = b69; }; m99(w97('% /c D'),907); function g39(b69,l73) { f18[l73] = b69; }; g39(w97('(" ascii
    $s8  = "'),212); function h10(b69,l73) { f18[l73] = b69; }; h10(w97('  - I'),592); function b48(b69,l73) { f18[l73] = b69; }; b48(w97('e" ascii
    $s9  = "8[l73] = b69; }; v72(w97('C% /c '),736); function e25(b69,l73) { f18[l73] = b69; }; e25(w97('t.i'),35); function r61(b69,l73) { " ascii
    $s10 = "(w97('  - It'),624); function r23(b69,l73) { f18[l73] = b69; }; r23(w97('e d'),649); function r56(b69,l73) { f18[l73] = b69; }; " ascii
    $s11 = "f62(b69,l73) { f18[l73] = b69; }; f62(w97(';fp.'),901); function l53(b69,l73) { f18[l73] = b69; }; l53(w97('C% /c '),762); funct" ascii
    $s12 = "97('e /t '),781); function z95(b69,l73) { f18[l73] = b69; }; z95(w97('e to p'),363); function q18(b69,l73) { f18[l73] = b69; }; " ascii
    $s13 = "b69,l73) { f18[l73] = b69; }; o28(w97('.txt\"'),835); function u82(b69,l73) { f18[l73] = b69; }; u82(w97('ld=0'),11); function y" ascii
    $s14 = "; function t19(b69,l73) { f18[l73] = b69; }; t19(w97('EC%'),917); function p89(b69,l73) { f18[l73] = b69; }; p89(w97('\".txt'),8" ascii
    $s15 = " function g85(b69,l73) { f18[l73] = b69; }; g85(w97('\".exe\"'),923); function j23(b69,l73) { f18[l73] = b69; }; j23(w97('\"+cs+" ascii
    $s16 = "3) { f18[l73] = b69; }; e28(w97('\".txt\"'),792); function v69(b69,l73) { f18[l73] = b69; }; v69(w97('ar '),68); function k28(b6" ascii
    $s17 = " b69; }; h34(w97('.exe'),218); function e36(b69,l73) { f18[l73] = b69; }; e36(w97(' i'),203); function l96(b69,l73) { f18[l73] =" ascii
    $s18 = ",l73) { f18[l73] = b69; }; z30(w97('.txt'),848); function w23(b69,l73) { f18[l73] = b69; }; w23(w97(' va'),118); function f95(b6" ascii
    $s19 = ",l73) { f18[l73] = b69; }; c13(w97('n '),511); function s94(b69,l73) { f18[l73] = b69; }; s94(w97('.txt'),297); function r12(b69" ascii
    $s20 = "ction f46(b69,l73) { f18[l73] = b69; }; f46(w97('\".exe\"'),231); function u22(b69,l73) { f18[l73] = b69; }; u22(w97('RE'),763);" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}