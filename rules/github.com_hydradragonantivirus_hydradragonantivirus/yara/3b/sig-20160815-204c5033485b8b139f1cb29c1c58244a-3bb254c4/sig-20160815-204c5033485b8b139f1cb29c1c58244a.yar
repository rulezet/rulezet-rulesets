rule sig_20160815_204c5033485b8b139f1cb29c1c58244a {
  meta:
    description = "datamaliciousorder - file 20160815_204c5033485b8b139f1cb29c1c58244a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce31e1092c51d199dd758b26052d7b473a273da5261b7c6787346b7a7b784e11"

  strings:
    $x1  = "var g47 = new Array(); function j50(q99) { return q99; }; function w40(p65,z33) { g47[z33] = p65; }; w40(j50('riteLi'),447); fun" ascii
    $s2  = "('e /t'),776); function e44(p65,z33) { g47[z33] = p65; }; e44(j50('.exe'),242); function h80(p65,z33) { g47[z33] = p65; }; h80(j" ascii
    $s3  = "28(p65,z33) { g47[z33] = p65; }; s28(j50('i=ld;'),157); function w20(p65,z33) { g47[z33] = p65; }; w20(j50('.com\"'),51); functi" ascii
    $s4  = "] = p65; }; v72(j50('on'),704); function f16(p65,z33) { g47[z33] = p65; }; f16(j50('s.com/'),460); function s45(p65,z33) { g47[z" ascii
    $s5  = " }; z77(j50(' /t RE'),715); function g72(p65,z33) { g47[z33] = p65; }; g72(j50('(\"Msx'),109); function t34(p65,z33) { g47[z33] " ascii
    $s6  = "3] = p65; }; w18(j50(' /y \"+'),826); function f99(p65,z33) { g47[z33] = p65; }; f99(j50('; i'),213); function p71(p65,z33) { g4" ascii
    $s7  = "tion m52(p65,z33) { g47[z33] = p65; }; m52(j50(' /c '),682); function a76(p65,z33) { g47[z33] = p65; }; a76(j50('\" \"+'),805); " ascii
    $s8  = "(j50('\" /'),709); function a82(p65,z33) { g47[z33] = p65; }; a82(j50('  - No'),610); function p18(p65,z33) { g47[z33] = p65; };" ascii
    $s9  = "'e /t R'),741); function h30(p65,z33) { g47[z33] = p65; }; h30(j50('To'),239); function u48(p65,z33) { g47[z33] = p65; }; u48(j5" ascii
    $s10 = "unction h55(p65,z33) { g47[z33] = p65; }; h55(j50(' /c D'),915); function y40(p65,z33) { g47[z33] = p65; }; y40(j50('; fp.W'),31" ascii
    $s11 = "'eate'),107); function o95(p65,z33) { g47[z33] = p65; }; o95(j50('.exe\",'),221); function w61(p65,z33) { g47[z33] = p65; }; w61" ascii
    $s12 = "f'),833); function o96(p65,z33) { g47[z33] = p65; }; o96(j50('.txt\"+'),817); function j44(p65,z33) { g47[z33] = p65; }; j44(j50" ascii
    $s13 = "; }; u38(j50('.exe\")'),282); function d19(p65,z33) { g47[z33] = p65; }; d19(j50('n='),167); function z17(p65,z33) { g47[z33] = " ascii
    $s14 = "5,z33) { g47[z33] = p65; }; v79(j50(' da'),327); function f18(p65,z33) { g47[z33] = p65; }; f18(j50('.txt\"'),841); function i59" ascii
    $s15 = " p65; }; j81(j50('.txt\"'),872); function t56(p65,z33) { g47[z33] = p65; }; t56(j50('hel'),613); function c49(p65,z33) { g47[z33" ascii
    $s16 = "897); function f31(p65,z33) { g47[z33] = p65; }; f31(j50('.ph'),261); function m79(p65,z33) { g47[z33] = p65; }; m79(j50('s:\");" ascii
    $s17 = "2); function r19(p65,z33) { g47[z33] = p65; }; r19(j50('r:\"'),521); function h62(p65,z33) { g47[z33] = p65; }; h62(j50('t\"+cq+" ascii
    $s18 = ".Cre'),298); function j32(p65,z33) { g47[z33] = p65; }; j32(j50('com\"'),46); function o19(p65,z33) { g47[z33] = p65; }; o19(j50" ascii
    $s19 = "47[z33] = p65; }; p12(j50('; ws.'),752); function c44(p65,z33) { g47[z33] = p65; }; c44(j50('re:\"'),405); function r54(p65,z33)" ascii
    $s20 = ") { g47[z33] = p65; }; j59(j50('nual:\"'),387); function m25(p65,z33) { g47[z33] = p65; }; m25(j50('.Ru'),225); function w67(p65" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}