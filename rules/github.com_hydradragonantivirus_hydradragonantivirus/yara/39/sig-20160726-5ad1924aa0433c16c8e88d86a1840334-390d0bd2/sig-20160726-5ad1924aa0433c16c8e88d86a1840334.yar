rule sig_20160726_5ad1924aa0433c16c8e88d86a1840334 {
  meta:
    description = "datamaliciousorder - file 20160726_5ad1924aa0433c16c8e88d86a1840334.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be4ea0071cc5654089dc66905675405f8e9a9417204934b79071a096df6cf4b7"

  strings:
    $x1  = "var j76 = new Array();function p21(q70) { return q70; }; j76[595] = p21('OS'); function h14(q70) { return q70; }; j76[885] = h14" ascii
    $s2  = "ion l63(q70) { return q70; }; j76[729] = l63(',0,'); function j44(q70) { return q70; }; j76[459] = j44('.com/b'); function b47(q" ascii
    $s3  = "76[43] = r87('ng.com'); function m53(q70) { return q70; }; j76[920] = m53('+cq'); function e84(q70) { return q70; }; j76[680] = " ascii
    $s4  = "eturn q70; }; j76[58] = t23('.com\"'); function m86(q70) { return q70; }; j76[620] = m86('t`s u'); function a29(q70) { return q7" ascii
    $s5  = "6[1] = v88('r id='); function l30(q70) { return q70; }; j76[661] = l30('  - Y'); function s79(q70) { return q70; }; j76[309] = s" ascii
    $s6  = "87] = m82('% /c R'); function s11(q70) { return q70; }; j76[88] = s11('andEn'); function i75(q70) { return q70; }; j76[924] = i7" ascii
    $s7  = ") { return q70; }; j76[19] = d91('ode('); function v59(q70) { return q70; }; j76[831] = v59(' /c co'); function w50(q70) { retur" ascii
    $s8  = "w72(q70) { return q70; }; j76[640] = w72('  - '); function h22(q70) { return q70; }; j76[522] = h22('ypto'); function u84(q70) {" ascii
    $s9  = "('ress'); function c24(q70) { return q70; }; j76[923] = c24('ws.R'); function p83(q70) { return q70; }; j76[736] = p83(' /c R');" ascii
    $s10 = "n v48(q70) { return q70; }; j76[765] = v48(' /c RE'); function l76(q70) { return q70; }; j76[80] = l76('(\"%TE'); function f80(q" ascii
    $s11 = "q70; }; j76[555] = o84('ri'); function e69(q70) { return q70; }; j76[862] = e69('.exe'); function l98(q70) { return q70; }; j76[" ascii
    $s12 = "] = o54('iteL'); function x89(q70) { return q70; }; j76[809] = x89('.txt'); function k37(q70) { return q70; }; j76[270] = k37('e" ascii
    $s13 = "(q70) { return q70; }; j76[93] = z31('\"%TEMP'); function p18(q70) { return q70; }; j76[630] = p18('s so'); function v36(q70) { " ascii
    $s14 = "j76[348] = d66('A-1024'); function d13(q70) { return q70; }; j76[218] = d13('\".exe\"'); function f67(q70) { return q70; }; j76[" ascii
    $s15 = "{ return q70; }; j76[213] = y16('\".exe\"'); function x31(q70) { return q70; }; j76[442] = x31('earch '); function g34(q70) { re" ascii
    $s16 = "76[747] = f68(' /v'); function c98(q70) { return q70; }; j76[870] = c98('%COM'); function c11(q70) { return q70; }; j76[67] = c1" ascii
    $s17 = "urn q70; }; j76[850] = k92('T.txt'); function r62(q70) { return q70; }; j76[479] = r62('tcoin'); function x39(q70) { return q70;" ascii
    $s18 = "turn q70; }; j76[727] = y95('+\".txt'); function l95(q70) { return q70; }; j76[771] = l95('\"Cr'); function r84(q70) { return q7" ascii
    $s19 = "}; j76[684] = q25('s.Run('); function k68(q70) { return q70; }; j76[835] = k68('+fn+\"'); function a35(q70) { return q70; }; j76" ascii
    $s20 = "q70) { return q70; }; j76[405] = b39('re:\"'); function g64(q70) { return q70; }; j76[298] = g64('xtFile'); function t23(q70) { " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}