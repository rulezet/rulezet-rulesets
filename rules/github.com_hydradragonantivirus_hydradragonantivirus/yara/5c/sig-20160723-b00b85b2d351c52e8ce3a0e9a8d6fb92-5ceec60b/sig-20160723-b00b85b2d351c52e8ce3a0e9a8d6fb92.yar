rule sig_20160723_b00b85b2d351c52e8ce3a0e9a8d6fb92 {
  meta:
    description = "datamaliciousorder - file 20160723_b00b85b2d351c52e8ce3a0e9a8d6fb92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0c6c22b7947c29ecaa5225b0851e8fb6095f94d0b827724b0d680b9de60ab91"

  strings:
    $x1  = "var o77 = new Array();function a36(i83,p49) { o77[p49] = i83; }; a36('://\"', 165); function f46(i83,p49) { o77[p49] = i83; }; f" ascii
    $s2  = "nd', 180); function t92(i83,p49) { o77[p49] = i83; }; t92(' /t R', 777); function p90(i83,p49) { o77[p49] = i83; }; p90('e:\");'" ascii
    $s3  = "p49] = i83; }; y31('.dll', 95); function z57(i83,p49) { o77[p49] = i83; }; z57('rypt', 763); function k61(i83,p49) { o77[p49] = " ascii
    $s4  = "83,p49) { o77[p49] = i83; }; s79(' /F', 779); function q70(i83,p49) { o77[p49] = i83; }; q70('.Run(', 901); function w15(i83,p49" ascii
    $s5  = "77[p49] = i83; }; e88('coin w', 403); function q17(i83,p49) { o77[p49] = i83; }; q17('.com', 57); function u60(i83,p49) { o77[p4" ascii
    $s6  = "function y21(i83,p49) { o77[p49] = i83; }; y21('.com', 43); function m75(i83,p49) { o77[p49] = i83; }; m75('var f', 868); functi" ascii
    $s7  = " { o77[p49] = i83; }; s65(' /c \"+', 848); function q65(i83,p49) { o77[p49] = i83; }; q65('  htt', 458); function e48(i83,p49) {" ascii
    $s8  = "77[p49] = i83; }; j86(' /t RE', 744); function u81(i83,p49) { o77[p49] = i83; }; u81('/co', 168); function m31(i83,p49) { o77[p4" ascii
    $s9  = "nction l58(i83,p49) { o77[p49] = i83; }; l58('cq+fn+', 851); function a94(i83,p49) { o77[p49] = i83; }; a94(' /c DE', 905); func" ascii
    $s10 = "('C% /c ', 733); function a47(i83,p49) { o77[p49] = i83; }; a47('var c', 13); function w33(i83,p49) { o77[p49] = i83; }; w33('+" ascii
    $s11 = "on l64(i83,p49) { o77[p49] = i83; }; l64('de(34', 18); function s89(i83,p49) { o77[p49] = i83; }; s89(' - I', 625); function n72" ascii
    $s12 = " function x89(i83,p49) { o77[p49] = i83; }; x89('; w', 889); function u17(i83,p49) { o77[p49] = i83; }; u17(' /t RE', 719); func" ascii
    $s13 = "unction i93(i83,p49) { o77[p49] = i83; }; i93('L ', 604); function e43(i83,p49) { o77[p49] = i83; }; e43('% /c ', 797); function" ascii
    $s14 = "73('); w', 912); function k49(i83,p49) { o77[p49] = i83; }; k49('\"+', 768); function e33(i83,p49) { o77[p49] = i83; }; e33(' - " ascii
    $s15 = "y35(i83,p49) { o77[p49] = i83; }; y35('fp', 471); function j51(i83,p49) { o77[p49] = i83; }; j51('  - ', 594); function e55(i83," ascii
    $s16 = "9] = i83; }; g50('o.op', 160); function n68(i83,p49) { o77[p49] = i83; }; n68('% /c c', 823); function n26(i83,p49) { o77[p49] =" ascii
    $s17 = "p49] = i83; }; g19('.exe', 909); function v80(i83,p49) { o77[p49] = i83; }; v80('var', 533); function i52(i83,p49) { o77[p49] = " ascii
    $s18 = "function h69(i83,p49) { o77[p49] = i83; }; h69('.exe\")', 279); function i15(i83,p49) { o77[p49] = i83; }; i15('(); ', 684); fun" ascii
    $s19 = "); function b88(i83,p49) { o77[p49] = i83; }; b88('REG A', 690); function k25(i83,p49) { o77[p49] = i83; }; k25('\".txt', 788); " ascii
    $s20 = ", 593); function z92(i83,p49) { o77[p49] = i83; }; z92('%TEMP', 90); function k27(i83,p49) { o77[p49] = i83; }; k27('nal', 338);" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}