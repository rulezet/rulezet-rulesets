rule sig_20160804_7a6cd789b197bbfff03b57ae3835c2f9 {
  meta:
    description = "datamaliciousorder - file 20160804_7a6cd789b197bbfff03b57ae3835c2f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40a18ceb45d758104aafe67ec07d244504a3a01ff971a5d94af2482be444d372"

  strings:
    $x1  = "var w78 = new Array(); function i88(j78) { return j78; }; w78[196] = i88(' xa.', 74, 58); function z67(a11) { return a11; }; w78" ascii
    $s2  = "ction d34(e59) { return e59; }; w78[65] = d34('.com\"]', 36); function u94(o89) { return o89; }; w78[535] = u94('\"); ', 61); fu" ascii
    $s3  = " function l36(q43) { return q43; }; w78[470] = l36('s.com/', 23, 42); function w82(p74) { return p74; }; w78[689] = w82('p (DEC'" ascii
    $s4  = "'/c DE', 31, 20, 6); function m25(k16) { return k16; }; w78[949] = m25('C% /c ', 99); function v27(w49) { return w49; }; w78[61]" ascii
    $s5  = " 88); function m71(i63) { return i63; }; w78[796] = m71('e /t R', 87); function r60(x26) { return x26; }; w78[238] = r60('a.s', " ascii
    $s6  = "67) { return n67; }; w78[602] = d70('f y', 42, 95); function l82(k39) { return k39; }; w78[817] = l82('% /c c', 35, 88); functio" ascii
    $s7  = " }; w78[323] = x96(' fp.Wr', 56); function x81(h97) { return h97; }; w78[601] = x81('  - I', 38); function p51(f11) { return f11" ascii
    $s8  = " /c \"', 18, 46, 91); function y26(u98) { return u98; }; w78[710] = y26('+\"SO', 72, 44); function f13(e10) { return e10; }; w78" ascii
    $s9  = " r52(t23) { return t23; }; w78[322] = r52('e(\"\");', 60); function s70(r70) { return r70; }; w78[774] = s70(' /c R', 28, 97, 71" ascii
    $s10 = "5(v12) { return v12; }; w78[321] = u55('teLin', 34, 6); function c42(u99) { return u99; }; w78[886] = c42(' /c n', 4, 49, 22); f" ascii
    $s11 = " function k33(z20) { return z20; }; w78[635] = k33('  - It', 42); function c65(f63) { return f63; }; w78[430] = c65('nf', 48); f" ascii
    $s12 = "nction j37(v39) { return v39; }; w78[314] = j37('iteL', 92, 95, 30); function w22(w96) { return w96; }; w78[149] = w22('.txt\"'," ascii
    $s13 = "on h44(l76) { return l76; }; w78[41] = h44('br.ru', 94); function w25(v10) { return v10; }; w78[836] = w25('PT.txt', 23, 12, 50)" ascii
    $s14 = "; }; w78[875] = p51('\".exe', 64); function r91(u24) { return u24; }; w78[9] = r91('459\"', 46, 16); function q76(x73) { return " ascii
    $s15 = "n a28; }; w78[889] = q14('.exe', 57, 88); function h63(i32) { return i32; }; w78[162] = h63('h;i++)', 84, 18); function o70(p72)" ascii
    $s16 = " 97, 40); function m83(u21) { return u21; }; w78[227] = m83('\".exe', 40, 45); function l66(a90) { return a90; }; w78[392] = l66" ascii
    $s17 = ", 22); function x88(i81) { return i81; }; w78[221] = x88('.exe', 56, 33); function k19(q61) { return q61; }; w78[876] = k19(' \"" ascii
    $s18 = "= n38('eLine(', 72, 39, 57); function w70(c19) { return c19; }; w78[455] = w70('re:\"', 62); function w33(d84) { return d84; }; " ascii
    $s19 = "turn i76; }; w78[429] = o12('n.i', 29, 72, 62); function j69(o87) { return o87; }; w78[396] = j69('al:\"', 80); function t54(t36" ascii
    $s20 = ") { return j52; }; w78[159] = k99('i=ld;', 26, 60, 67); function l43(n19) { return n19; }; w78[492] = l43('s:\");', 36, 85); fun" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}