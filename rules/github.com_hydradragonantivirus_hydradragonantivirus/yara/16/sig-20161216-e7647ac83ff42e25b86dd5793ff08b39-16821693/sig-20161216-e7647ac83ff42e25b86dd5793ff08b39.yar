rule sig_20161216_e7647ac83ff42e25b86dd5793ff08b39 {
  meta:
    description = "datamaliciousorder - file 20161216_e7647ac83ff42e25b86dd5793ff08b39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36ff04b94eaf405c350a5fba9ad18150f64df806c99fed38840ca97d1f1b4f33"

  strings:
    $s1  = "function cheburgenTLg2(cheburgenGZv2) {eval(\"/*@cc_on var cheburgenRLu7 = new Date() @*/\");cheburgenRLu7[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``2``v``Z``G``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``)``\\x22``i``7``l``h``0``n``h``/``m``o``c``.``z``i``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``)``1``r``B``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``1``h``N``M``n``e``g``r``u``b``e``h``c`` ``+`` ``0``k" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``)``\\x22``\\x22`` ``+`` ``6``m``C``n``e``g``r``u``b`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"}``;``h``t``a``P``t``r``o``h``S``.``9``q``G``n``e``g``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``j``Z``J``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``2``v``Z``G``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"/``*``@`` ``}``;``7``x``S``N``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"}``;``h``t``a``P``t``r``o``h``S``.``9``q``G``n``e``g``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``1``+``1``=``0``r``Y``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTLg2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``i``Z``n" ascii
    $s20 = "function cheburgenTLg2(cheburgenGZv2) {eval(\"/*@cc_on var cheburgenRLu7 = new Date() @*/\");cheburgenRLu7[\"setUTC\"+\"Seconds" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}